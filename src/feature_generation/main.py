"""The main program that runs gSpan."""
# -*- coding=utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from src.feature_generation.feature_generation import *
import os
import sys

from src.feature_generation.gSpan.gspan_mining.gspan import gSpan




def main(FLAGS=None):
    """Run gSpan."""
    #
    # if FLAGS is None:
    #     FLAGS, _ = parser.parse_known_args(args=sys.argv[1:])
    #
    # if not os.path.exists(FLAGS.database_file_name):
    #     print('{} does not exist.'.format(FLAGS.database_file_name))
    #     sys.exit()

    gs = gSpan(
        min_support=0.5,
        max_support=0.4,
        is_undirected=False,
        min_num_vertices=2
    )

    gs.run()
    # print('\nfrequent dub: {}'.format(g.))
    # print(g.)
    gs.time_stats()
    create_features_file(gs.result)


# [[(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_TOPLEVEL:'))], [(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_TOPLEVEL:')),(frm=2, to=3, vevlb=('', 'FILE_OF', 'Filesystem:File:'))], [(frm=0, to=1, vevlb=('AST:AST_IF_ELEM:', 'PARENT_OF', 'AST:AST_IF:'))], [(frm=0, to=1, vevlb=('AST:AST_IF_ELEM:', 'PARENT_OF', 'AST:AST_IF:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_STMT_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_CONST:', 'PARENT_OF', 'AST:AST_ARG_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_NAME:', 'PARENT_OF', 'AST:AST_CONST:'))], [(frm=0, to=1, vevlb=('AST:AST_ASSIGN:', 'FLOWS_TO:', 'AST:AST_CALL:'))]]
# out [[(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_TOPLEVEL:'))], [(frm=0, to=1, vevlb=('AST:AST_IF:', 'PARENT_OF', 'AST:AST_STMT_LIST:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_TOPLEVEL:')),(frm=2, to=3, vevlb=('', 'FILE_OF', 'Filesystem:File:'))], [(frm=0, to=1, vevlb=('AST:AST_IF_ELEM:', 'PARENT_OF', 'AST:AST_IF:'))], [(frm=0, to=1, vevlb=('AST:AST_IF_ELEM:', 'PARENT_OF', 'AST:AST_IF:')),(frm=1, to=2, vevlb=('', 'PARENT_OF', 'AST:AST_STMT_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_CONST:', 'PARENT_OF', 'AST:AST_ARG_LIST:'))], [(frm=0, to=1, vevlb=('AST:AST_NAME:', 'PARENT_OF', 'AST:AST_CONST:'))], [(frm=0, to=1, vevlb=('AST:AST_ASSIGN:', 'FLOWS_TO:', 'AST:AST_CALL:'))]]


if __name__ == '__main__':
    gs = main()

