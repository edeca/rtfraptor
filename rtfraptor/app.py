"""
Example implementation of a console application using rtfraptor.engine.
"""
import argparse
import json
import logging
from .engine import OfficeDebugger
from .utils import sha256_file


def save_json(input_fn, output_fn, objects):
    """
    Save a JSON representation of the output to the given file.
    """
    sha256 = sha256_file(input_fn)
    info = {"input_file": input_fn, "sha256": sha256, "objects": {}}

    index = 0
    for _, obj in objects.items():
        info['objects'][index] = obj
        index += 1

    with open(output_fn, 'w') as fh:
        json.dump(info, fh)


def main():
    """
    Main entry point, parses arguments and calls the RTF debugging engine.
    """

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
        "--json",
        help="JSON output file (default: disabled)",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--timeout",
        help="how long to wait before killing target executable (default: 10 seconds)",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--save-path",
        help="directory to save OLEv1 objects (default: objects are not saved)",
        type=str,
        default=None,
    )

    args = parser.parse_args()
    fmt = '%(levelname)s %(message)s'

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format=fmt)
    else:
        logging.basicConfig(level=logging.INFO, format=fmt)

    engine = OfficeDebugger(args.executable)
    engine.timeout = args.timeout
    objects = engine.run(args.file, save_path=args.save_path)

    if args.json:
        save_json(args.file, args.json, objects)


if __name__ == "__main__":
    main()
