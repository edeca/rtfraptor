# -*- coding: utf-8 -*-
"""
The main RTF debugging engine, uses winappdbg to run Word (or
another Office executable) and obtain information about OLEv1
objects as they are loaded.
"""
import hashlib
import logging
import os
from collections import OrderedDict
from time import time
from oletools.common.clsid import KNOWN_CLSIDS
from winappdbg import Debug, EventHandler, System, win32
from winappdbg.win32 import PVOID
from .utils import bytes_to_clsid


class CustomEventHandler(EventHandler):  # pylint: disable=too-few-public-methods
    """
    Event handler used by winappdbg to instrument the target executable.
    """
    save_path = None  # type: str

    # The list of modules and functions we want to hook.
    _hooks = {
        "ole32.dll": {
            "OleLoad": {'args': 4, 'hook': '_hook_load'},
            "OleConvertOLESTREAMToIStorage": {'args': 3, 'hook': '_hook_data_conversion'},
            "OleGetAutoConvert": {'args': 2, 'hook': '_hook_guid_conversion'},
        }
    }

    # The memory location of the most recent pStg object is stored here,
    # enabling tracking of objects between OleLoad and OleGetAutoConvert
    # (which will also be called from elsewhere).  We assume there can
    # be no irrelevant calls to OleGetAutoConvert once OleLoad is called.
    _last_pstg = None

    def __init__(self, logger):
        super(CustomEventHandler, self).__init__()
        self._log = logger
        self.objects = OrderedDict()

    def _hook_load(self, _event, _ra, pstg, _riid, _pclientsite, _ppvobjx):
        """
        Event hook for OleLoad.  This function simply saves the pStg address
        allowing tracking between different calls.

        A nicer solution would be to identify how to extract the class ID
        directly from the pStg object, which implements IStorage.  The later
        hook could then be removed.
        """
        self._last_pstg = pstg

    def _hook_guid_conversion(self, event, _ra, clsid_old, _pclsid_new):
        """
        Event hook for OleGetAutoConvert.  This allows us to obtain the actual
        class id which is being loaded.

        This hook will also be called from other places.  We reduce the risk
        of false positives by only logging details if OleLoad has just been
        called, by checking for self._last_pstg.
        """
        process = event.get_process()
        clsid_bytes = process.read(clsid_old, 16)
        clsid = bytes_to_clsid(clsid_bytes)

        if self._last_pstg:
            info = self.objects[self._last_pstg]
            info['class_id'] = clsid

            if clsid in KNOWN_CLSIDS:
                self._log.warning("Suspicious OLE object loaded, class id %s (%s)",
                                  clsid, KNOWN_CLSIDS[clsid])
                self._log.warning("Object size is %d, SHA256 is %s", info['size'], info['sha256'])
                info['description'] = KNOWN_CLSIDS[clsid]
            else:
                self._log.warning("Object found but not on blacklist %s", clsid)
                info['description'] = "Unknown (not blacklisted)"

            self._last_pstg = None

    def _hook_data_conversion(self, event, _ra, lpolestream, pstg, _ptd):
        """
        Event hook for OleConvertOLESTREAMToIStorage.  This allows retrieval
        of the raw OLEv1 object from memory.  Information on objects is
        stored using pstg (the location in memory) as a unique key.
        """
        info = {}

        process = event.get_process()
        hasher = hashlib.sha256()

        # Follow the lpOleStream parameter
        # TODO: Test this on 64-bit Office where pointer sizes will be different
        #       and identify how this affects offset of length
        data_addr = process.peek_pointer(process.peek_pointer(lpolestream + 8))
        info['size'] = process.peek_dword(lpolestream + 12)
        data = process.read(data_addr, info['size'])

        # Save the SHA256 of the object
        hasher.update(data)
        info['sha256'] = hasher.hexdigest()

        if self.save_path:
            filename = os.path.join(self.save_path, info['sha256'])
            with open(filename, 'wb') as fh:
                fh.write(data)

        self.objects[pstg] = info

        self._log.debug("Dumping data from 0x%08x, destination 0x%08x, length %d, hash %s",
                        data_addr, pstg, info['size'], info['sha256'])

    def _apply_hooks(self, event, hooks):
        """
        Add hooks to the specified module.
        """
        module = event.get_module()
        pid = event.get_pid()

        for func, options in hooks.items():
            address = module.resolve(func)
            if address:
                self._log.debug("Address of %s is 0x%08x", func, address)
                signature = (PVOID,) * options['args']
                callback = getattr(self, options['hook'])
                event.debug.hook_function(pid, address, callback, signature=signature)
            else:
                self._log.error("Could not find function %s to hook", func)
                return False

        return True

    def load_dll(self, event):
        """
        This callback occurs when the debugged process loads a new module (DLL)
        into memory.  At this point we insert hooks (breakpoints) that can
        inspect relevant functions as they are called.
        """
        module = event.get_module()

        for dll, hooks in self._hooks.items():
            if module.match_name(dll):
                self._log.debug("Process loaded %s, hooks exist for this module", module.get_name())
                self._apply_hooks(event, hooks)
                # TODO: Check if the above was successful and die if not


class OfficeDebugger(object):  # pylint: disable=too-few-public-methods
    """
    The main debugging engine, which can be called from other modules.
    """

    executable = None  # type: str
    timeout = 10  # type: int

    def __init__(self, executable, logger=None):

        # TODO: Ensure executable is executable
        # TODO: Check 32-bit vs. 64-bit?
        self.executable = executable
        if logger:
            self._log = logger
        else:
            self._log = logging.getLogger(__name__)

    def run(self, target_file, save_path=None):
        """
        Run the executable with the provided file, optionally saving all OLEv1
        parts that are encountered.
        """

        # TODO: Ensure target_file is readable

        opts = [self.executable, target_file]
        handler = CustomEventHandler(self._log)
        handler.save_path = save_path

        with Debug(handler, bKillOnExit=True) as debug:

            # Ensure the target application dies if the debugger is killed
            System.set_kill_on_exit_mode(True)
            max_time = time() + self.timeout

            try:
                debug.execv(opts)
            except WindowsError:
                self._log.error("Could not run Office application, check it is 32-bit")

            try:
                while debug.get_debugee_count() > 0 and time() < max_time:
                    try:
                        # Get the next debug event.
                        debug.wait(1000)

                    except WindowsError, exc:
                        if exc.winerror in (win32.ERROR_SEM_TIMEOUT,
                                            win32.WAIT_TIMEOUT):
                            continue
                        raise

                    # Dispatch the event and continue execution.
                    try:
                        debug.dispatch()
                    finally:
                        debug.cont()
            finally:
                debug.stop()

        return handler.objects
