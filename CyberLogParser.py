#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Launcher / entrypoint for CyberLogParser Pro 2026.

Run:
    python CyberLogParser.py
"""

from cyberlogparsey import CyberLogParserApp


def main() -> None:
    app = CyberLogParserApp()
    app.run()


if __name__ == "__main__":
    main()

