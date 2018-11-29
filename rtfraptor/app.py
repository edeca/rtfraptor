import argparse
import logging
from .engine import office_debugger

def main():

    parser = argparse.ArgumentParser(
        description=("Rip OLEv1 objects from obfuscated RTF files, by "
                     "debugging Word and dumping from memory")
    )
    parser.add_argument(
        "--debug",
        help="enable debug logging (default: False)",
        action='store_true',
        default=False,
    )
    parser.add_argument(
        "--executable",
        type=str,
        help="target executable to run, typically WINWORD.EXE (full path required)",
        required=True,
    )
    parser.add_argument(
        "--file",
        help="RTF file to open",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--timeout",
        help="how long to wait before killing target executable (default: 10 seconds)",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--disable-save",
        help="don't save OLEv1 objects to disk (default: objects are saved)",
        action='store_true',
        default=False,
    )

    # TODO: JSON output

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    office_debugger(args.executable, args.file, timeout=args.timeout, save_objs=not args.disable_save)


if __name__ == "__main__":
    main()
