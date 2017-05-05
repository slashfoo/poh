__versionstr__ = '0.1.6'
__version__ = tuple([int(ver_i) for ver_i in __versionstr__.split('.')])

from poh import (print_execution_results,
                 read_result_files,
                 redirect_streams,
                 remote_execute,
                 run_poh)
