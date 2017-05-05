#!/usr/bin/env python
"""Run commands specified on remote servers using ssh."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import collections
import datetime
import errno
import fcntl
import itertools
import logging
import operator
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import re

import poh

import termios

_CMD_EPILOG = """\
(+) means that the option may be specified multiple times

Additional servers will be read one per line if '-' is present in the
server list specified in the command line or stdin is not a terminal
(as when being piped the output of another command).

When reading stdin or files, lines starting with '#' will be ignored.

Notes on option presedence:
* -q implies --no-color
* -1 (dash-one), -L, and -W are ignored if -r or -q are specified.
* -L is ignored if -1 (dash-one) is specified.
"""

__MODULENAME = 'poh' if __name__ == '__main__' else __name__.rsplit('.', 1)[-1]
LOG = logging.getLogger(__MODULENAME)
logging.basicConfig(datefmt='%Y-%m-%dT%H:%M:%S',
                    format='%(asctime)s.%(msecs)d - %(levelname)-8s - '
                           '%(filename)s:%(lineno)-4d - '
                           '%(module)s:%(funcName)s - %(message)s')

_EASY_LOGGING_LEVELS = [
    ('DEBUG', logging.DEBUG,),
    ('INFO', logging.INFO,),
    ('WARNING', logging.WARNING,),
    ('ERROR', logging.ERROR,),
    ('CRITICAL', logging.CRITICAL,),
]
_MAX_LOGLVL = len(_EASY_LOGGING_LEVELS)

_PRETTY_ARGUMENTS_FORMAT = """\
color = {color!r}
debug = {debug!r}
dry_run = {dry_run!r}
verbosity = {verbosity!r}
output_dir = {output_dir!r}
keep_output = {keep_output!r}
transpose_output = {transpose_output!r} 
quiet_output = {quiet_output!r}
raw_output = {raw_output!r}
one_line = {one_line!r}
long_output = {long_output!r}
wide_output = {wide_output!r}
ssh_config = {ssh_config!r}
servers: {servers}
cmd_files: {cmd_files}
positional_was_first: {positional_was_first}
commands (only showing printable chars): {commands}
"""

_PY2_SYMLINK_ATTACK_WARN = """
You are using python2, your platform may be susceptible to symlink attacks.
Please do some research on the implications on running this utility in a
multi-user environment.

To not show this warning set the environment variable POH_IGNORE_PY2_WARNS to
something other than the string 'no'.
"""

_MESSAGE_WRAPPER = textwrap.TextWrapper()
_MESSAGE_WRAPPER.expand_tabs = False
_MESSAGE_WRAPPER.replace_whitespace = False
_MESSAGE_WRAPPER.drop_whitespace = False

_ERROR_WRAPPER = textwrap.TextWrapper()
_ERROR_WRAPPER.expand_tabs = False
_ERROR_WRAPPER.replace_whitespace = False
_ERROR_WRAPPER.drop_whitespace = False
_ERROR_WRAPPER.subsequent_indent = '       '
_ERROR_WRAPPER.initial_indent = '       '

_ESC_CODE_FMT = '\x1b[{}m'

_COLORS = {
    'black': 0,
    'red': 1,
    'green': 2,
    'yellow': 3,
    'blue': 4,
    'magenta': 5,
    'cyan': 6,
    'white': 7,
}

_CODES = {
    'global_reset': 0,
    'bold': 1,
    'fg_reset': 39,
    'bg_reset': 49,
}
_CODES.update({
    'fg_{}'.format(color): code+30
    for color, code in _COLORS.items()
})
_CODES.update({
    'bg_{}'.format(color): code+40
    for color, code in _COLORS.items()
})

_TIME_HEADER_FORMAT = """\
  Start time = {start_local} {tz_name} ({start_utc} UTC)
    End time = {end_local} {tz_name} ({end_utc} UTC)
Elapsed time = {elapsed:0.3f}s
"""

_TIME_HEADER_FORMAT_WITH_COLOR = """\
\x1b[34m  Start time\x1b[39m \x1b[30m=\x1b[0m \x1b[37m{start_local} {tz_name}\x1b[0m \x1b[30m({start_utc} UTC)\x1b[0m
\x1b[34m    End time\x1b[39m \x1b[30m=\x1b[0m \x1b[37m{end_local} {tz_name}\x1b[0m \x1b[30m({end_utc} UTC)\x1b[0m
\x1b[34mElapsed time\x1b[39m \x1b[30m=\x1b[0m {elapsed:0.3f}s
"""

def _escaped_with(original_string, pre=None, post=None):
    if pre is None and post is None:
        return original_string

    escaped_string = ''

    if pre is not None:
        pre_codes = [str(_CODES[code_string]) for code_string in pre]
        escaped_string += _ESC_CODE_FMT.format(';'.join(pre_codes))

        if post is None:
            post = ['global_reset']

    escaped_string += original_string

    if post is not None:
        post_codes = [str(_CODES[code_string]) for code_string in post]
        escaped_string += _ESC_CODE_FMT.format(';'.join(post_codes))

    return escaped_string

def _get_terminal_size(file_descriptor_num):
    try:
        term_columns, term_lines = shutil.get_terminal_size()
    except AttributeError:
        term_columns, term_lines = None, None
        LOG.warning("shutil doesn't have get_terminal_size, the executable"
                    " is probably using Python2. Falling back to termios.")

    try:
        term_lines, term_columns = struct.unpack('hh', fcntl.ioctl(
            file_descriptor_num, termios.TIOCGWINSZ, '1234'
        ))
    except IOError as exc:
        if errno.ENOTTY == exc.errno:
            LOG.debug("fd %d is not a tty Falling back to environment"
                      " variables", file_descriptor_num)
        else:
            LOG.exception("Unhandled IOError when determining term size"
                          " falling back to environment variables")
        term_columns, term_lines = None, None
    except Exception:
        LOG.exception("Unhandled Exception when determining term size"
                      " falling back to environment variables")
        term_columns, term_lines = None, None

    if term_columns is None:
        try:
            term_columns = int(os.environ.get('COLUMNS'))
        except (TypeError, ValueError):
            LOG.warning("Failed to set terminal width from COLUMNS environment"
                        " variable.")
            term_columns = None

    if term_lines is None:
        try:
            term_lines = int(os.environ.get('LINES'))
        except (TypeError, ValueError):
            LOG.warning("Failed to set terminal height from LINES environment"
                        " variable.")
            term_lines = None

    return term_columns, term_lines

def _set_rootlogger_verbosity(verbosity):
    rootlogger = logging.getLogger('')
    default_level = 3

    desired_level = default_level - verbosity
    if desired_level < 0:
        desired_level = 0
    elif desired_level > len(_EASY_LOGGING_LEVELS) - 1:
        desired_level = -1

    level_name, level_num = _EASY_LOGGING_LEVELS[desired_level]
    rootlogger.setLevel(level_num)
    LOG.info('Set logging level on root logger to %s', level_name)

def _show_on_stderr(message, error=False):
    message_wrapper = _MESSAGE_WRAPPER

    paragraphs = message.splitlines()

    first_par = None
    if error and len(paragraphs) > 0:
        message_wrapper = _ERROR_WRAPPER
        first_par = _MESSAGE_WRAPPER.fill("Error: " + paragraphs.pop(0))

    formatted_paragraphs = [message_wrapper.fill(par) for par in paragraphs]
    if first_par is not None:
        formatted_paragraphs.insert(0, first_par)

    formatted_message = '\n'.join(formatted_paragraphs)
    if message.endswith('\n'):
        formatted_message += '\n'

    try:
        print(formatted_message, file=sys.stderr, flush=True)
    except TypeError:
        # python2 print function doesn't have flush
        print(formatted_message, file=sys.stderr)

def _show_error_messages(msgs_list):
    for msg in msgs_list:
        _show_on_stderr(msg+'\n', error=True)

def _potential_dir(path_string):
    absolute_path = os.path.abspath(path_string)

    if os.path.isdir(absolute_path):
        return absolute_path

    if os.path.exists(absolute_path):
        message = "{!r} exists and is not a directory.".format(path_string)
        raise argparse.ArgumentTypeError(message)

    try:
        os.makedirs(absolute_path, mode=0o700)
    except OSError:
        LOG.exception("Unhandled OSError occurred when attempting to"
                      " create directory %r",
                      absolute_path)
        message = "Directory {!r} couldn't be created.".format(path_string)
        raise argparse.ArgumentTypeError(message)
    else:
        return absolute_path

def _get_servers(server_lists):
    for server in itertools.chain(*server_lists):
        if ',' in server:
            for serv in server.split(','):
                yield serv
            # The proper idiom in python3 is the "yield from" below
            # Kept from...yield  for python2 compat
            # yield from server.split(',')
        else:
            yield server

def _printable_string(original_string):
    import codecs
    escaped_repr = repr(codecs.encode(original_string, 'utf-8'))
    escaped_string = escaped_repr[escaped_repr.index("'")+1:-1]
    escaped_string = escaped_string.replace("\\\\", "\\")
    escaped_string = escaped_string.replace("\\'", "'")
    if escaped_string.endswith(r'\n'):
        escaped_string = escaped_string[:-2]
    return escaped_string

def _prettified_args(args_dict):
    pretty_dict = dict(args_dict)

    if not pretty_dict['cmd_files']:
        pretty_dict['cmd_files'] = 'None'
    else:
        pretty_dict['cmd_files'] = ''.join(['\n    - {}'.format(f.name)
                                            for f in pretty_dict['cmd_files']])

    pretty_dict['servers'] = ''.join(['\n    - {}'.format(s)
                                      for s in pretty_dict['servers']])

    commands_dict = pretty_dict.pop('commands')

    pretty_commands = []
    for commands_file, commands_list in commands_dict.items():
        fname = commands_file if commands_file else 'command line positional'
        file_string = '\n    - {} ({}):'.format(fname, len(commands_list))
        file_string += ''.join([
            '\n      {}:$ {}'.format(cmd_num, _printable_string(command))
            for cmd_num, command in enumerate(commands_list, 1)
        ])
        pretty_commands.append(file_string)

    pretty_dict['commands'] = ''.join(pretty_commands)

    pretty_paragraph = _PRETTY_ARGUMENTS_FORMAT.format(**pretty_dict)
    pretty_arguments = ''.join(['\n    {}'.format(line)
                                for line in pretty_paragraph.splitlines()])

    return pretty_arguments

def _create_argparser():
    # TODO: add an option to upload an sh and execute it instead
    #       of a command_file or a command
    # TODO: add --ssh-args for passing arbitrary stuff to ssh
    # TODO: add a --synch to print results as they arrive
    # TODO: change --transpose to make execution order be transposed as well?
    # TODO: add a --timeout
    parser = argparse.ArgumentParser(
        prog=__MODULENAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__, epilog=_CMD_EPILOG
    )
    add_arg = parser.add_argument
    add_arg('-V', '--version', action='version',
            version='{} v{}'.format(__MODULENAME, poh.__versionstr__),
            help="Show version string and exit")
    add_arg('-x', '--debug', action='store_true',
            help="Include debugging information. (implies maximum verbosity)")
    add_arg('-v', '--verbose', action='count', default=0, dest='verbosity',
            help="Be more verbose. (+)")
    add_arg('--no-color', action='store_false', dest='color',
            help="Disable colored output. Automatic if stdout is not a term")
    add_arg('-t', '--transpose-output', action='store_true',
            help="Print outputs grouped by commands. (default is by server)")
    add_arg('-1', '--one-line', action='store_true',
            help="(dash-one) Print only the first line of output of the first"
                 " command right after a summary of return codes for all"
                 " commands.")
    add_arg('-L', '--long-output', '--all-lines', action='store_true',
            help="Print all lines of the output of the commands."
                 " The default behavior is to show only last lines of output"
                 " To a maximum equals to terminal height, or LINES"
                 " environment variable")
    add_arg('-W', '--wide-output', '--wide-lines', action='store_true',
            help="Don't truncate lines."
                 " The default behavior is to truncate lines so that they fit"
                 " on the terminal, or COLUMNS environment variable."
                 " Indicating the truncation with '...' (three dots)")
    add_arg('-k', '--keep-output', action='store_true',
            help="Keep temp files (stdout, stderr, and retval) of commands")
    add_arg('-o', '--output-dir', action='store', default=None,
            help="Directory for temp files. (implies -k)", type=_potential_dir)
    add_arg('-S', '--servers', metavar='SERVER', nargs='+', action='append',
            help="Servers to run commands on. (+)", dest='servers', default=[])
    add_arg('-F', '--ssh-config', action='store', default=None,
            type=argparse.FileType(),
            help="Use the ssh configuration in the specified file."
                 " Otherwise let system use the default")
    add_arg('-f', '--commands-from', action='append', nargs=1, default=[],
            type=argparse.FileType(), dest='cmd_files', metavar='CMD_FILE',
            help="Load commands from the file specified. (+)")
    add_arg('pos_cmds', nargs='*', metavar='COMMAND',
            help="Command to run on the servers as a positional arg."
                 " May need to be specified after a '--' pseudo-argument.")
    add_arg('-D', '--dry-run', action='store_true',
            help="Don't affect any local or remote system, only parse args"
                 " and show what would have happened")
    add_arg('-r', '--raw-output', action='store_true',
            help="Of the commands, send all stdout to stdout, and stderr to"
                 " stderr prefixed with servername and ':\\t'"
                 " (a colon, and a tab character)")
    add_arg('-q', '--quiet-output', action='store_true',
            help="Same as '-r/--raw-output' but without server name prefix")

    return parser

def _read_commands_files(commands_files):
    commands_dictionary = collections.OrderedDict()

    for commands_file in commands_files:
        file_name = commands_file.name
        LOG.debug('Processing command file at %s', file_name)
        whole_file = commands_file.read()
        whole_file = whole_file.replace('\\\n', ' ')
        lines_in_file = whole_file.splitlines()

        commands_in_file = [' '.join(shlex.split(line))+'\n'
                            for line in lines_in_file
                            if not line.startswith('#') and line != '']

        num_of_commands = len(commands_in_file)
        total_lines = len(lines_in_file)
        num_of_blanks = lines_in_file.count('')
        num_of_comments = total_lines - num_of_blanks - num_of_commands

        LOG.debug('File had %d command(s), %d blanks, '
                  ' and %d comments in %d lines',
                  num_of_commands, num_of_blanks, num_of_comments,
                  total_lines)
        LOG.debug('Adding %d command(s) for %r', num_of_commands, file_name)

        commands_dictionary[file_name] = commands_in_file

    return commands_dictionary

def _remove_output_dir(output_dir):
    try:
        error_out_on_remove = not shutil.rmtree.avoids_symlink_attacks
    except AttributeError:
        if 'POH_IGNORE_PY2_WARNS' in os.environ:
            poh_ignore_py2_warns = os.environ['POH_IGNORE_PY2_WARNS']
            LOG.debug('POH_IGNORE_PY2_WARNS was defined in execution'
                      ' environment set to %r', poh_ignore_py2_warns)
        else:
            poh_ignore_py2_warns = 'no'
        if poh_ignore_py2_warns == 'no':
            import warnings
            warnings.warn(_PY2_SYMLINK_ATTACK_WARN)
        error_out_on_remove = False
    if error_out_on_remove:
        _show_error_messages([(
            'Not removing temp directory at {!r}.'
            ' Platform suceptible to symlink attacks.'
            ' You can read more at:'
            ' https://docs.python.org/3/library/shutil.html'
            ' Please remove it manually.'
        ).format(output_dir)])
    else:
        LOG.debug("Removing output directory at %r.", output_dir)
        shutil.rmtree(output_dir)

def _count_lines(filepath):
    num_line = 0
    with open(filepath, 'r') as input_file:
        for num_line, _ in enumerate(input_file, 1):
            pass
    num_lines = num_line
    return num_lines

def _read_one_line(filepath):
    first_line = None
    with open(filepath, 'r') as input_file:
        first_line = input_file.readline()
    return first_line

def _read_entire_file(filepath):
    file_contents = None
    with open(filepath, 'r') as input_file:
        file_contents = input_file.read()
    return file_contents

def _read_int_from_file(filepath):
    try:
        number = int(_read_one_line(filepath))
    except ValueError:
        LOG.debug("Tried to read number from %r but got an error",
                  filepath)
        number = -1
    return number

def read_result_files(output_dir, one_line=False):
    results = {}
    total_lines = 0

    import glob
    reader_funcs = {'retval': _read_int_from_file,
                    'stdout': _read_entire_file,
                    'stderr': _read_entire_file,}

    if one_line:
        reader_func = _read_one_line

        reader_funcs['stdout'] = reader_func
        reader_funcs['stderr'] = reader_func

    restypes = reader_funcs.keys()
    globs = {filetype:'*.?.{}'.format(filetype) for filetype in restypes}
    filepaths = {filetype: sorted(glob.glob(os.path.join(output_dir, pat)))
                 for filetype, pat in globs.items()}
    counts = {filetype: len(filelist)
              for filetype, filelist in filepaths.items()}

    LOG.debug("Found %d temp files in %r (%s)",
              sum(counts.values()), output_dir,
              ', '.join(['{}: {}'.format(key, value)
                         for key, value in counts.items()]))

    for filetype, filelist in filepaths.items():
        LOG.debug("Reading files of type %r", filetype)
        reader_func = reader_funcs.get(filetype)
        for resultfile in filelist:
            server, cmdnum_str, _ = os.path.basename(resultfile).rsplit('.', 2)
            cmdnum = int(cmdnum_str)

            server_results = results.setdefault(server, {})
            cmd_results = server_results.setdefault(cmdnum, {
                rt:None for rt in restypes
            })

            lines_in_file = _count_lines(resultfile)
            LOG.debug("%r: %r", filetype, resultfile)
            if filetype == 'stderr':
                contents_string = reader_func(resultfile)
                contents_string = re.sub(
                    r'^ControlSocket .*?\n?$', '', contents_string
                )
                cmd_results[filetype] = (
                    contents_string,
                    lines_in_file,
                )
            else:
                cmd_results[filetype] = (
                    reader_func(resultfile),
                    lines_in_file,
                )

            total_lines += lines_in_file

    LOG.debug("There were a total of %d lines in results files", total_lines)

    return results

def _time_strings(timestamp):
    local_time = datetime.datetime.fromtimestamp(timestamp)
    local_string = local_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]

    utc_time = datetime.datetime.utcfromtimestamp(timestamp)
    utc_string = utc_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:23]
    return local_string, utc_string

def _std_streams_lines(cmd_results, long_output=False, limit_lines=25):
    output_lines = []

    stdout, stdout_ln = cmd_results['stdout']
    stderr, stderr_ln = cmd_results['stderr']

    if not long_output:
        lnum = 1
        stderr_lines = []
        for lnum, line in enumerate(stderr.splitlines(), 1):
            stderr_lines.append('      X '+line)
        if lnum > limit_lines:
            output_lines.append('      X ...')
            output_lines.extend(stderr_lines[-limit_lines:])
            output_lines.append(
                '      X Output clipped to the last {} of {} lines'.format(
                    limit_lines, lnum
                ),
            )
        else:
            output_lines.extend(stderr_lines)

        stdout_lines = []
        for lnum, line in enumerate(stdout.splitlines(), 1):
            stdout_lines.append('      > '+line)
        if lnum > limit_lines:
            output_lines.append('      > ...')
            output_lines.extend(stdout_lines[-limit_lines:])
            output_lines.append(
                '      > Output clipped to the last {} of {} lines'.format(
                    limit_lines, lnum
                ),
            )
        else:
            output_lines.extend(stdout_lines)

    else:
        output_lines.extend(['      X '+line for line in stderr.splitlines()])
        output_lines.extend(['      > '+line for line in stdout.splitlines()])
    if stdout_ln + stderr_ln > 0:
        output_lines.append('')
    return output_lines

def print_execution_results(outputs, commands, one_line=False,
                            long_output=False, wide_output=False,
                            transpose_output=False, color=False,
                            times=(None, None,)):
    output_lines = []
    start_time, end_time = times

    time_header_format = _TIME_HEADER_FORMAT
    if color:
        time_header_format = _TIME_HEADER_FORMAT_WITH_COLOR

    if start_time is not None and end_time is not None:
        tz_name = time.tzname[1] if time.daylight else time.tzname[0]
        start_local, start_utc = _time_strings(start_time)
        end_local, end_utc = _time_strings(end_time)
        output_lines.extend(time_header_format.format(
            start_local=start_local,
            start_utc=start_utc,
            end_local=end_local,
            end_utc=end_utc,
            tz_name=tz_name,
            elapsed=end_time - start_time,
        ).splitlines())
        output_lines.append('')

    term_columns, term_lines = _get_terminal_size(sys.stdout.fileno())
    if term_columns is None:
        wide_output = True
    if term_lines is None:
        long_output = True

    LOG.debug("Terminal dimensions = width: %d, height: %d",
              term_columns, term_lines)

    cmd_map = []
    for cmdfile, cmdlist in commands.items():
        cmd_map.extend([
            ((cmdfile, cmd_num,), cmd) for cmd_num, cmd in enumerate(cmdlist)
        ])
    cmd_map = {cmd_idx:(gcmd_num, cmd,)
               for gcmd_num, (cmd_idx, cmd,) in enumerate(cmd_map, 1)}

    if cmd_map:
        if color:
            output_lines.append(_escaped_with("Commands run:", ['fg_white']))
        else:
            output_lines.append("Commands run:")
        output_lines.extend([
            "  {:4d}. {}".format(gcmd_num, _printable_string(cmd))
            for gcmd_num, cmd in sorted(cmd_map.values())
        ])
        output_lines.append('')

    if color:
        output_lines.append(_escaped_with("Results:", ['fg_white']))
    else:
        output_lines.append("Results:")
    if one_line:
        _format_retval = lambda x: '{:^5s}'.format('[{}]'.format(x))
        if color:
            def _format_retval(retval):
                if retval == 0:
                    fmts = ['fg_green']
                else:
                    fmts = ['fg_red']
                bracketed = '[{}]'.format(retval)
                formatted_string = '{:^5}'.format(bracketed)
                colorized_string = _escaped_with(formatted_string, pre=fmts)
                return colorized_string

        LOG.debug("Output set to one-line, ignoring transpose_output setting.")
        line_proto_format = textwrap.dedent("""\
        {{server_name:>{server_width}s}}:  {{retval_block}}  {{output_line}}
        """)
        output_cells = []
        for server, results in outputs.items():
            cells = [server]
            cells.append([_format_retval(results[cmd]['retval'][0])
                          for cmd in sorted(results.keys())])
            cells.append(results[1]['stdout'][0].split('\n', 1)[0])
            output_cells.append(cells)
        widest_server = max([len(server) for server in outputs.keys()])
        line_format = line_proto_format.rstrip('\n').format(
            server_width=widest_server+4
        )

        output_lines.extend([
            line_format.format(server_name=svname,
                               retval_block=''.join(retvals),
                               output_line=output_line.rstrip('\n'))
            for svname, retvals, output_line in sorted(output_cells)
        ])
    else:
        def _format_retval(retval, color):
            formatted_string = '[RETVAL={}]'.format(retval)
            if color:
                if retval == 0:
                    formatted_string = _escaped_with(formatted_string,
                                                     ['fg_green'])
                else:
                    formatted_string = _escaped_with(formatted_string,
                                                     ['fg_red'])
            return formatted_string
        if transpose_output:
            outputs_by_num = {}
            for srv, srvres in outputs.items():
                for cmd_num, cmdres in srvres.items():
                    gcmdres = outputs_by_num.setdefault(cmd_num, {})
                    gcmdres[srv] = cmdres

            for gcmd_num, cmd in sorted(cmd_map.values()):
                output_lines.append(
                    "  cmd#{:<4d}$ {}".format(gcmd_num, _printable_string(cmd))
                )
                cmdres = outputs_by_num.get(gcmd_num, [])
                for srv_num, (srv, srvres) in enumerate(sorted(cmdres.items()), 1):
                    retval = srvres['retval'][0]
                    stdout_ln = srvres['stdout'][1]
                    stderr_ln = srvres['stderr'][1]
                    output_lines.append(
                        "      srv#{:<4d} {:12s} (l#:{}/{}) - {}".format(
                            srv_num,
                            _format_retval(retval, color),
                            stderr_ln,
                            stdout_ln,
                            srv
                        )
                    )
                    output_lines.extend(
                        _std_streams_lines(srvres,
                                           long_output=long_output,
                                           limit_lines=term_lines)
                    )
        else:
            cmds_by_num = {gcmd_num:_printable_string(cmd)
                           for gcmd_num, cmd in sorted(cmd_map.values())}
            for srv_num, (srv, srvres) in enumerate(sorted(outputs.items()), 1):
                output_lines.append("  srv#{:<4d}- {}".format(srv_num, srv))
                for cmd_num, cmdres in sorted(srvres.items()):
                    retval = cmdres['retval'][0]
                    stdout_ln = cmdres['stdout'][1]
                    stderr_ln = cmdres['stderr'][1]
                    output_lines.append(
                        "      cmd#{:<4d} {:12s} (l#:{}/{}) $ {}".format(
                            cmd_num,
                            _format_retval(retval, color),
                            stderr_ln,
                            stdout_ln,
                            cmds_by_num[cmd_num]
                        )
                    )
                    output_lines.extend(
                        _std_streams_lines(cmdres,
                                           long_output=long_output,
                                           limit_lines=term_lines)
                    )

    if not wide_output:
        if not color:
            _shortened = lambda line: line[:term_columns-3]+'...'
        else:
            def _shortened(line):
                escaped_chars_num = sum(map(len, re.findall('\x1b\[.*?m', line)))
                if term_columns+escaped_chars_num >= len(line):
                    return line
                return line[:term_columns+escaped_chars_num-3]+'...'
        output_lines = [_shortened(line)
                        if len(line) > term_columns else line
                        for line in output_lines]

    report = '\n'.join(output_lines)

    print(report)

def remote_execute(servers, commands, output_dir, ssh_config=None):
    run_queue = itertools.product(
        servers,
        enumerate(itertools.chain(*commands.values()), 1)
    )

    result_files = []
    child_procs = []

    try:
        for server, (cmd_num, cmd) in run_queue:

            rvpath, outpath, errpath = [
                os.path.join(output_dir,
                             '.'.join([server, str(cmd_num), filetype]))
                for filetype in ['retval', 'stdout', 'stderr']
            ]
            rvfile, outfile, errfile = [open(filepath, 'w') for filepath in [
                rvpath, outpath, errpath
            ]]
            result_files.extend([rvfile, outfile, errfile])

            LOG.debug("Running cmd %d on %s", cmd_num, server)
            cmdargs = []
            cmdargs.append('ssh')
            if ssh_config:
                cmdargs.append('-F{}'.format(ssh_config))
            cmdargs.extend([server, cmd])
            child_procs.append(
                (rvfile,
                 subprocess.Popen(cmdargs, stdout=outfile, stderr=errfile),)
            )

        for rvfile, childproc in child_procs:
            childproc.communicate()
            rvfile.write('{:d}\n'.format(childproc.returncode))

    finally:
        for result_file in result_files:
            try:
                result_file.close()
            except IOError:
                LOG.exception("Failed to close fd %r", result_file)

def redirect_streams(output_dir, quiet, transpose_output=False,
                     color=False):
    import glob
    globs = {filetype:'*.?.{}'.format(filetype) for filetype in [
        'retval', 'stdout', 'stderr'
    ]}
    filepaths = {filetype: sorted(glob.glob(os.path.join(output_dir, pat)))
                 for filetype, pat in globs.items()}

    filepath_tuples = []
    for fpath in itertools.chain(filepaths['stderr'], filepaths['stdout']):
        srv, cmd_num, stream = os.path.basename(fpath).rsplit('.', 2)
        dest_stream = sys.stdout if stream == 'stdout' else sys.stderr
        filepath_tuples.append((srv, cmd_num, stream, dest_stream, fpath))

    retvals = {}
    for fpath in filepaths['retval']:
        srv, cmd_num, stream = os.path.basename(fpath).rsplit('.', 2)
        retvals[(srv, cmd_num)] = _read_int_from_file(fpath)

    sortkey = operator.itemgetter(0, 1, 2)
    if transpose_output:
        sortkey = operator.itemgetter(1, 0, 2)

    filepath_tuples = sorted(filepath_tuples, key=sortkey)

    if quiet:
        for srv, cmd_num, _, dest_stream, fpath in filepath_tuples:
            with open(fpath, 'r') as resultfile:
                shutil.copyfileobj(resultfile, dest_stream)
        return

    line_format = '{}:\t{}'
    no_stderr = set()

    for srv, cmd_num, _, dest_stream, fpath in filepath_tuples:
        if not color:
            srv = srv
        elif retvals[(srv, cmd_num)] == 0:
            srv = _escaped_with(srv, ['fg_green'])
        else:
            srv = _escaped_with(srv, ['fg_red'])
        if dest_stream is sys.stderr and os.stat(fpath).st_size == 0:
            no_stderr.add((srv, cmd_num,))
        elif dest_stream is sys.stdout and os.stat(fpath).st_size == 0:
            if (srv, cmd_num,) in no_stderr:
                dest_stream.write(line_format.format(srv, _escaped_with(
                    '<EMPTY OUTPUT>', ['fg_yellow']
                ) if color else '<EMPTY OUTPUT>'))
                dest_stream.write('\n')
            continue
        elif dest_stream is sys.stderr:
            def writefunc(line):
                out_line = line
                if line.startswith('ControlSocket ') and \
                   'already exists, disabling multiplexing' in line:
                    LOG.debug("Got ControlSocket message from ssh,"
                              " removing from stderr. Line: %r", line)
                    return
                if color:
                    out_line = _escaped_with(out_line, ['fg_red'])
                out_line = line_format.format(srv, out_line)
                dest_stream.write(out_line)
        else:
            writefunc = lambda line: dest_stream.write(
                line_format.format(srv, line)
            )
        with open(fpath, 'r') as resultfile:
            for line in resultfile.readlines():
                writefunc(line)

def run_poh(servers, commands, ssh_config=None, output_dir=None,
            keep_output=False, quiet_output=False, raw_output=False,
            one_line=False, long_output=False, wide_output=False,
            transpose_output=False, color=False):

    if output_dir is not None:
        keep_output = True
    else:
        LOG.debug("Creating temporary directory.")
        output_dir = tempfile.mkdtemp()
        LOG.debug("Created temporary directory at %r.", output_dir)

    start_time = time.time()
    if ssh_config is None and 'SSH_CONFIG' in os.environ:
        ssh_config = os.environ['SSH_CONFIG']
    remote_execute(servers, commands, output_dir, ssh_config)
    end_time = time.time()
    if raw_output or quiet_output:
        redirect_streams(output_dir, quiet_output, transpose_output, color)
    else:
        outputs = read_result_files(output_dir, one_line)
        print_execution_results(outputs, commands, one_line, long_output,
                                wide_output, transpose_output, color,
                                times=(start_time, end_time,))

    if keep_output:
        print("\nOutput located at: {}".format(output_dir))
    else:
        _remove_output_dir(output_dir)

def main_exe():
    """Do argument parsing and hand over to operational functions."""
    parser = _create_argparser()

    if not sys.argv[1:]:
        parser.print_usage()
        sys.exit(64)

    args = parser.parse_args()

    if args.ssh_config:
        # TODO: change this to be a path, rather than a file
        args.ssh_config = args.ssh_config.name

    args.keep_output = args.keep_output or (args.output_dir is not None)

    args.servers = {server for server in _get_servers(args.servers)}
    if not sys.stdin.isatty() or '-' in args.servers:
        args.servers.discard('-')
        args.servers |= {line.rstrip('\n') for line in sys.stdin.readlines()
                         if not line.startswith('#') and line != ''}
    args.servers = sorted(args.servers)

    err_msgs = []
    if not args.servers:
        err_msgs.append("You must specify at least one server")

    args.pos_cmds = [cmd for cmd in args.pos_cmds if cmd != ""]
    if not args.pos_cmds and not args.cmd_files:
        err_msgs.append("You must specify at least one command or cmd_file")

    if err_msgs:
        _show_error_messages(err_msgs)
        parser.print_usage()
        sys.exit(64)

    if not sys.stdout.isatty():
        args.long_output = True
        args.wide_output = True
        args.color = False

    if args.debug:
        args.verbosity = _MAX_LOGLVL
    _set_rootlogger_verbosity(args.verbosity)

    args.commands = collections.OrderedDict()
    if args.pos_cmds:
        LOG.debug('Adding %d command(s) to be executed.', len(args.pos_cmds))
        args.commands[None] = args.pos_cmds
        first_pos = sys.argv.index(args.pos_cmds[0])
    else:
        first_pos = len(sys.argv)

    if args.cmd_files:
        LOG.debug('Adding commands from %d files.', len(args.cmd_files))
        args.cmd_files = list(itertools.chain(*args.cmd_files))
        args.commands.update(_read_commands_files(args.cmd_files))
        first_cmd = sys.argv.index(args.cmd_files[0].name)
    else:
        first_cmd = len(sys.argv)

    args.positional_was_first = first_pos < first_cmd
    if not args.positional_was_first and args.pos_cmds:
        args.commands.pop(None)
        args.commands[None] = args.pos_cmds

    # TODO: save a representation of them here at preproc, rather than at
    # different points in execution _printable_string for all commands

    LOG.debug("Finished parsing and validating command line arguments.")

    pretty_arguments = _prettified_args(args.__dict__)
    LOG.debug("Using the following execution parameters: %s", pretty_arguments)

    if args.dry_run:
        _show_on_stderr('This is a dry-run, not executing commands.')
        _show_on_stderr(
            "Would've executed {} commands on {} servers".format(
                sum([len(cmdlist) for cmdlist in args.commands.values()]),
                len(args.servers)
            )
        )
        sys.exit(0)

    try:
        run_poh(args.servers, args.commands, args.ssh_config,
                args.output_dir, args.keep_output,
                args.quiet_output, args.raw_output,
                args.one_line, args.long_output, args.wide_output,
                args.transpose_output, args.color)
    except IOError as exc:
        if errno.EPIPE == exc.errno:
            sys.stdout.close()
            sys.stderr.close()
        else:
            LOG.exception("Unhandled IOError running main function. Re-raising.")
            raise
    except:
        LOG.exception("Unhandled exception running main function. Re-raising.")
        raise
    else:
        sys.exit(0)

if __name__ == '__main__':
    main_exe()
