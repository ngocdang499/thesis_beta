"""The main program that runs gSpan."""
# -*- coding=utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from src.feature_generation.feature_generation import *
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
        min_support=0.4,
        max_support=0.5,
        is_undirected=False,
        min_num_vertices=2
    )

    gs.run()
    print("out", gs.result)
    # print('\nfrequent dub: {}'.format(g.))
    # print(g.)
    import_graph_to_neo4j(None)
    generate_features_from_code(gs.result)
    gs.time_stats()

    return gs


if __name__ == '__main__':
    gs = main()

