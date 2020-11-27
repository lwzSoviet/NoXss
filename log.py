#!/usr/bin/env python

"""
Output
"""

import logging
import re
import sys

class ColorizingStreamHandler(logging.StreamHandler):
    # color names to indices
    color_map = {
        'black': 0,
        'red': 1,
        'green': 2,
        'yellow': 3,
        'blue': 4,
        'magenta': 5,
        'cyan': 6,
        'white': 7,
    }

    # levels to (background, foreground, bold/intense)
    level_map = {
        logging.DEBUG: (None, 'blue', False),
        logging.INFO: (None, 'green', False),
        logging.WARNING: (None, 'yellow', False),
        logging.ERROR: (None, 'red', False),
        logging.CRITICAL: ('red', 'white', False)
    }
    csi = '\x1b['
    reset = '\x1b[0m'
    bold = "\x1b[1m"
    disable_coloring = False

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty() and not self.disable_coloring

    def emit(self, record):
        try:
            message = self.format(record)
            stream = self.stream

            if not self.is_tty:
                if message and message[0] == "\r":
                    message = message[1:]
                stream.write(message)
            else:
                self.output_colorized(message)
            stream.write(getattr(self, 'terminator', '\n'))

            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except IOError:
            pass
        except:
            self.handleError(record)

    def output_colorized(self, message):
        self.stream.write(message)

    def _reset(self, message):
        if not message.endswith(self.reset):
            reset = self.reset
        elif self.bold in message:  # bold
            reset = self.reset + self.bold
        else:
            reset = self.reset

        return reset

    def colorize(self, message, levelno):
        if levelno in self.level_map and self.is_tty:
            bg, fg, bold = self.level_map[levelno]
            params = []

            if bg in self.color_map:
                params.append(str(self.color_map[bg] + 40))

            if fg in self.color_map:
                params.append(str(self.color_map[fg] + 30))

            if bold:
                params.append('1')

            if params and message:
                if message.lstrip() != message:
                    prefix = re.search(r"\s+", message).group(0)
                    message = message[len(prefix):]
                else:
                    prefix = ""

                message = "%s%s" % (prefix, ''.join((self.csi, ';'.join(params),
                                   'm', message, self.reset)))

        return message

    def format(self, record):
        message = logging.StreamHandler.format(self, record)
        return self.colorize(message, record.levelno)

LOGGER = logging.getLogger("")
LOGGER_HANDLER = None
try:
    class _ColorizingStreamHandler(ColorizingStreamHandler):
        def colorize(self, message, levelno):
            if levelno in self.level_map and self.is_tty:
                bg, fg, bold = self.level_map[levelno]
                params = []

                if bg in self.color_map:
                    params.append(str(self.color_map[bg] + 40))

                if fg in self.color_map:
                    params.append(str(self.color_map[fg] + 30))

                if bold:
                    params.append('1')

                if params and message:
                    match = re.search(r"\A(\s+)", message)
                    prefix = match.group(1) if match else ""
                    message = message[len(prefix):]

                    match = re.search(r"\[([A-Z ]+)\]", message)  # log level
                    if match:
                        level = match.group(1)
                        if message.startswith(self.bold):
                            message = message.replace(self.bold, "")
                            reset = self.reset + self.bold
                            params.append('1')
                        else:
                            reset = self.reset
                        message = message.replace(level, ''.join((self.csi, ';'.join(params), 'm', level, reset)), 1)

                        match = re.search(r"\A\s*\[([\d:]+)\]", message)  # time
                        if match:
                            time = match.group(1)
                            message = message.replace(time, ''.join((self.csi, str(self.color_map["cyan"] + 30), 'm', time, self._reset(message))), 1)

                        match = re.search(r"\[(#\d+)\]", message)  # counter
                        if match:
                            counter = match.group(1)
                            message = message.replace(counter, ''.join((self.csi, str(self.color_map["yellow"] + 30), 'm', counter, self._reset(message))), 1)

                        if level != "PAYLOAD":
                            if any(_ in message for _ in ("parsed DBMS error message",)):
                                match = re.search(r": '(.+)'", message)
                                if match:
                                    string = match.group(1)
                                    message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                            else:
                                match = re.search(r"\bresumed: '(.+\.\.\.)", message)
                                if match:
                                    string = match.group(1)
                                    message = message.replace("'%s" % string, "'%s" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                                else:
                                    match = re.search(r" \('(.+)'\)\Z", message) or re.search(r"output: '(.+)'\Z", message)
                                    if match:
                                        string = match.group(1)
                                        message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                                    else:
                                        for match in re.finditer(r"[^\w]'([^']+)'", message):  # single-quoted
                                            string = match.group(1)
                                            message = message.replace("'%s'" % string, "'%s'" % ''.join((self.csi, str(self.color_map["white"] + 30), 'm', string, self._reset(message))), 1)
                    else:
                        message = ''.join((self.csi, ';'.join(params), 'm', message, self.reset))

                    if prefix:
                        message = "%s%s" % (prefix, message)

                    message = message.replace("%s]" % self.bold, "]%s" % self.bold)  # dirty patch

            return message

    LOGGER_HANDLER = _ColorizingStreamHandler(sys.stdout)
except ImportError:
    LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)