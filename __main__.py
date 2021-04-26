from Utils.logs import *
from Utils.config import *
from Dataset.dataset_factory import *
from CodePropertyGraph.cpg import *


def cmd_create_set():
    print_banner("Building sets")

    global sets

    sel_ds = get_str('dataset', 'SelectedDataset')

    sets = get_dataset(sel_ds).get_sets()


def cmd_create_CPG(set_type, language, vuln_type):
    for filepath in sets[set_type][language][vuln_type]:
        if len(sets['flaw_dict'][language][vuln_type][filepath]) > 0:
            CPG.generate_CPG(filepath, sets['flaw_dict'][language][vuln_type][filepath])


def main():
    init("config.ini")
    cmd_create_set()
    cmd_create_CPG('training_set','PHP','XSS')
    # print(sets['flaw_dict']['PHP']['XSS']['data/SAMATE/XSS/CWE_79/unsafe/CWE_79__array-GET__func_http_build_query__Use_untrusted_data_propertyValue_CSS-span_Style_Property_Value.php'])
    # CPG.generate_CPG("/home/mn404/Documents/Thesis/Project/tools/phpjoern/test.php")


if __name__ == "__main__":
    main()
