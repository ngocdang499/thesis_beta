import json

from src.utils.logs import *
from src.utils.config import *
from src.dataset.dataset_factory import *
from src.utils.config import get_str

from src.feature_generation.feature_generation import *

from src.feature_generation.gSpan.gspan_mining.gspan import gSpan


def cmd_create_set():
    print_banner("Build sets")
    global sets
    sel_ds = get_str('dataset', 'SelectedDataset')
    sets = get_dataset(sel_ds).get_sets()


def cmd_create_CPG(set_type, language, vuln_type):
    print_banner("Generate CPGs and import to database")
    for filepath in sets[set_type][language][vuln_type]:
        CSVGraph.generate_CPG(filepath, vuln_type, sets['flaw_dict'][language][vuln_type][filepath])


def cmd_mine_frequent_pattern(min_support, max_support, target):
    print_banner("Mine frequent graph patterns")
    gs = gSpan(
        min_support=min_support,
        max_support=max_support,
        is_undirected=False,
        min_num_vertices=2
    )
    gs.run()
    gs.time_stats()

    patterns_file = get_str("processed_files", "PatternsFile")
    print_banner(f'Write patterns to {patterns_file}')
    write_patterns_to_file(gs.result)


def write_patterns_to_file(patterns_set):
    patterns_file = get_str("processed_files", "PatternsFile")
    with open(patterns_file, 'w') as f:
        f.write(json.dump(patterns_set))


def cmd_read_patterns_from_file():
    patterns_file = get_str("processed_files", "PatternsFile")
    if os.path.isfile(patterns_file):
        with open(patterns_file, 'r') as f:
            patterns_set = json.loads(f.read())
        return patterns_set
    else:
        print_warning("Unable to read patterns from file. File does not exist.")
        return None


def main():
    init("config.ini")
    # cmd_create_set()
    # cmd_create_CPG('training_set', 'PHP', 'SQLi')
    import_graph_to_neo4j("test.php")

if __name__ == "__main__":
    main()
