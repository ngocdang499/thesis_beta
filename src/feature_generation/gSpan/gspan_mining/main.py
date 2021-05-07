"""The main program that runs gSpan."""
# -*- coding=utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys

from config import parser
from gspan import gSpan


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
        min_support=0.06,
        max_support=0.2,
        is_undirected=False,
        min_num_vertices=3
    )

    gs.run()
    # print('\nfrequent dub: {}'.format(g.))
    # print(g.)
    gs.time_stats()

    return gs


if __name__ == '__main__':
    gs = main()

