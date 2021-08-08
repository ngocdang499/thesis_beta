import json
import pickle, random

import numpy as np

from src.utils.logs import *
from src.dataset.dataset_factory import *
from src.utils.tools import gen_ast_img

from src.feature_generation.feature_generation import *
from src.classification_model.batched_pca import *
from src.feature_generation.gSpan.gspan_mining.gspan import gSpan

from src.classification_model.train import *

from src.code_property_graph.pattern import *

def cmd_create_set(sel_ds):
    print_banner("Build sets")
    global sets
    sets = get_dataset(sel_ds).get_sets()


def cmd_gen_ast_img(filepath):
    gen_ast_img(filepath)


def cmd_create_CPG(set_type, language, vuln_type):
    print_banner("Generate CPGs and import to database")
    id_lst = []
    # nodes_file = get_str("csv_files", "Nodes_file")
    # x = []
    # y = []
    # import time
    # _time = []
    for filepath in sets[set_type][language][vuln_type]:
        # print(vuln_type)
        # count1 = len(open(filepath).readlines())
        # start_time = time.time()
        CSVGraph.generate_CPG(filepath, vuln_type, vuln_type + '_' + set_type, sets['flaw_dict'][language][vuln_type][filepath])
        # _time.append(time.time() - start_time)
        # count2 = len(open(nodes_file).readlines())
        # x.append(count1 - 10)
        # y.append(count2-1)

    # import matplotlib.pyplot as plt
    # import numpy as np
    #
    # # plotting the points
    # x = np.array(x)
    # plt.scatter(x, y)
    # m, b = np.polyfit(x, y, 1)
    # plt.plot(x, m * x + b)
    # # naming the x axis
    # plt.xlabel('Number of lines of code')
    # # naming the y axis
    # plt.ylabel('Number of node in generated CPG')
    #
    # # function to show the plot
    # plt.show()
    #
    # plt.scatter(x, _time)
    # m, b = np.polyfit(x, _time, 1)
    # plt.plot(x, m * x + b)
    # # naming the x axis
    # plt.xlabel('Number of lines of code')
    # # naming the y axis
    # plt.ylabel('Execution time for generating CPG (second)')
    #
    # # function to show the plot
    # plt.show()


def cmd_mine_frequent_pattern(min_support, max_support, target, mine_type=1):
    print_banner("Mine frequent graph patterns")
    gs = gSpan(
        mine_type=mine_type,
        min_support=min_support,
        max_support=max_support,
        is_undirected=False,
        min_num_vertices=2,
        target=target
    )
    gs.run()
    gs.time_stats()
    cmd_import_pattern_to_db(gs.result, target, mine_type)
    # print(gs.result)
    return gs.result.copy()

def cmd_import_pattern_to_db(gs_result, vuln_type, mine_type):
    print_banner("Import Patterns to DB")
    pt_lst = []
    for res in gs_result:
        pt = Pattern(json.dumps(str(res[0])), str(res[2]), res[1][0], res[1][1], vuln_type, mine_type)
        pt_lst.append(pt)
    Pattern.addPatterns(pt_lst)
    # gs1 = gSpan(
    #     min_support=min_support,
    #     max_support=max_support,
    #     is_undirected=False,
    #     min_num_vertices=2,
    #     target="Safe"
    # )
    # gs1.run()
    # gs1.time_stats()

    # patterns_file = get_str("processed_files", "PatternsFile")
    # print_banner(f'Write patterns to {patterns_file}')
    # tmp = gs.result.copy() + gs1.result.copy()
    # create_features_file(tmp)
    # write_patterns_to_file(gs.result)


def write_patterns_to_file(patterns_set, vuln_type):

    patterns_file = get_str("processed_files", f'{vuln_type}PatternsFile')
    with open(patterns_file, 'a') as f:
        for pattern in patterns_set:
            pt = pattern.pattern[1:-1].replace("frm", "'frm'")
            pt = pt.replace("to", "'to'")
            pt = pt.replace("vevlb", "'vevlb'")
            # pt = pt.replace("'", "\"")
            pt = pt.replace("))", "]}")
            pt = pt.replace("=(", ": [")
            pt = pt.replace(",(", ", {")
            pt = pt.replace("(", "{")
            pt = pt.replace("=", ": ")
            pt = pt.replace("\"", "\\\"")
            pt = pt.replace("\\\\\"", "\\\"")
            pt = pt.replace("'", "\"")
            f.write(pt+"\n")


def cmd_read_patterns_from_file(vuln_type):
    patterns_file = get_str("processed_files", f'{vuln_type}PatternsFile')
    if os.path.isfile(patterns_file):
        print("AAAAAAAAAAAAA\n")
        patterns_set = []
        with open(patterns_file, 'r') as f:
            lines = f.readlines()
            for l in lines:
                print(l)
                patterns_set.append(json.loads(l))
        return patterns_set
    else:
        print_warning("Unable to read patterns from file. File does not exist.")
        return None


def cmd_train_model(vuln_type, model_type, X_train, y_train, pca=None):
    print_banner(f'Train classifier model')

    if 0 < pca < len(y_train):
        pca = BatchedPCA(30)
        pca.partial_fit(X_train,y_train)
        # # #
        X_train = pca.transform(X_train)

    # Building and training the model
    classifier = select_model(vuln_type, model_type, X_train, y_train)

    return classifier


def cmd_test_model(vuln_type, model_name, model, X_test, y_test, pca):
    print_banner(f'Test classifier model')

    if 0 < pca < len(y_test):
        pca = BatchedPCA(30)
        pca.partial_fit(X_test,y_test)
        # # #
        X_test = pca.transform(X_test)

    y_pred = model.predict(X_test)
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # Generating accuracy, precision, recall and f1-score
    from sklearn.metrics import classification_report
    target_names = ['Safe', vuln_type]
    print(classification_report(y_test, y_pred, target_names=target_names))

    metrics.display_pr_curve(f'{vuln_type} {model_name}', model, X_test, y_test)


def cmd_save_model(vuln_type, model_name, model):
    print_banner(f'Save {model_name} classification model of {vuln_type}')

    model_file = get_str("saved_model", vuln_type)
    model_file = os.path.join(model_file, model_name + ".sav")

    pickle.dump(model, open(model_file, 'wb'))


def cmd_load_model(vuln_type, model_name):
    print_banner(f'Load {model_name} classification model of {vuln_type}')

    model_file = get_str("saved_model", vuln_type)
    model_file = os.path.join(model_file, model_name + ".sav")

    loaded_model = pickle.load(open(model_file, 'rb'))
    return loaded_model


def cmd_generate_feature_vector(filename, vuln_type):
    print_banner(f'Generate feature vector')

    import_graph_to_neo4j(filename)
    features = cmd_read_patterns_from_file(vuln_type)

    return generate_features_from_code(features)


def cmd_predict_file(filepath, vuln_type, model_name, display_ast=False):
    print_banner(f'Predict {vuln_type} in file with {model_name}')

    dataset_file = get_str("processed_files", f'{vuln_type}FeaturesFile')
    dataset = pd.read_csv(dataset_file, header=None)

    print(dataset)
    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values

    pca = BatchedPCA(30)
    pca.partial_fit(X, y)

    feature_vector = np.array(cmd_generate_feature_vector(filepath, vuln_type))

    feature_vector = [feature_vector]

    feature_vector = pca.transform(feature_vector)
    classifier = cmd_load_model(vuln_type, model_name)

    res = classifier.predict(feature_vector)
    return res


def main():
    init("config.ini")
    # cmd_create_set('SAMATE')
    # cmd_create_CPG('training_set', 'PHP', 'XSS')
    # cmd_create_CPG('training_set', 'PHP', 'SQLi')
    #
    # cmd_create_CPG('testing_set', 'PHP', 'XSS')
    # cmd_create_CPG('testing_set', 'PHP', 'SQLi')
    #
    # cmd_create_CPG('tuning_set', 'PHP', 'XSS')
    # cmd_create_CPG('tuning_set', 'PHP', 'SQLi')

#     print_banner("Mine Safe")
#     patterns = cmd_mine_frequent_pattern(0.5, 0.5, "Safe_XSS")
#     print(len(patterns))
# #     # write_patterns_to_file(patterns)
# # # #
# #     print_banner("Mine Unsafe")
#     patterns = cmd_mine_frequent_pattern(0.5, 0.5, "XSS")
#     print(len(patterns))
# # #     write_patterns_to_file(patterns)
# # #
# #     # print_banner("Mine Other")
#     patterns = cmd_mine_frequent_pattern(0.8, 0.2, "XSS", 2)
#     print(len(patterns))
# #     print_banner("Result patterns")
#     patterns_set = Pattern.getPatterns("XSS")
#     write_patterns_to_file(patterns_set, "XSS")
# #
# #
# #     # generate_features_from_code(patterns)
# #     # print(patterns)
#     pt = cmd_read_patterns_from_file('XSS')
# #     print(pt)
# # #     # # # # # #
# # # #     # # # create_features_file(pt, CSVGraph.getCPGsByType("Safe_SQLi", "training_set"), "SQLi")
#     create_features_file(pt, CSVGraph.getCPGsByType("XSS", "training_set") + CSVGraph.getCPGsByType("Safe_XSS", "training_set") + CSVGraph.getCPGsByType("SQLi", "tuning_set"), "XSS")
# #
#
#     print_banner("Mine Safe")
#     patterns = cmd_mine_frequent_pattern(0.5, 0.5, "Safe_SQLi")
#     print(len(patterns))
# #     # write_patterns_to_file(patterns)
# # # #
# #     print_banner("Mine Unsafe")
#     patterns = cmd_mine_frequent_pattern(0.5, 0.5, "SQLi")
#     print(len(patterns))
# # #     write_patterns_to_file(patterns)
# # #
# #     # print_banner("Mine Other")
#     patterns = cmd_mine_frequent_pattern(0.8, 0.2, "SQLi", 2)
#     print(len(patterns))
# #     print_banner("Result patterns")
#     patterns_set = Pattern.getPatterns("SQLi")
#     write_patterns_to_file(patterns_set, "SQLi")
#
#     pt = cmd_read_patterns_from_file('SQLi')
# #     print(pt)
# # #     # # # # # #
# # # #     # # # create_features_file(pt, CSVGraph.getCPGsByType("Safe_SQLi", "training_set"), "SQLi")
#     create_features_file(pt, CSVGraph.getCPGsByType("SQLi", "training_set") + CSVGraph.getCPGsByType("Safe_SQLi", "training_set") + CSVGraph.getCPGsByType("XSS", "tuning_set"), "SQLi")


    dataset_file = get_str("processed_files", "XSSFeaturesFile")
    dataset = pd.read_csv(dataset_file, header=None)
    # dataset = random.shuffle(dataset)
    dataset = dataset.sample(frac=1).reset_index(drop=True)
    print(dataset)
    # #
    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values
#     # #
    pca = BatchedPCA(30)
    pca.partial_fit(X,y)
#     # # # #
    print("vuln", np.count_nonzero(y))

    model = cmd_train_model("XSS", "SVM", X, y, 0)
    cmd_test_model("XSS", "SVM", model, X, y, 0)
#     # import src.classification_model.metrics
#     #
    cmd_save_model("XSS", "SVM", model)
#     # generate_features_from_code(pt)
#     # print(pt)
#     # if pt:
#     #     print("here")
#     #     create_features_file(pt)
#     # cmd_gen_ast_img("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-concatenation.php")
#     # import_graph_to_neo4j("test.php")
#
#     dataset_file = get_str("processed_files", "XSSFeaturesFile")
#     dataset = pd.read_csv(dataset_file, header=None)
#     # # #
#     X = dataset.iloc[:, :-1].values
#     y = dataset.iloc[:, -1].values
#     # # #
#     pca = BatchedPCA(30)
#     pca.partial_fit(X,y)
#     # # #
#     X = pca.transform(X)
#     model = cmd_load_model("XSS", "RDF")
#     # # #
#     y_pred = model.predict(X)
#     print(len(y_pred))
#     # # # Generating accuracy, precision, recall and f1-score
#     from sklearn.metrics import classification_report
#     target_names = ['Safe', 'XSS']
#     print(classification_report(y, y_pred, target_names=target_names))
#     #
    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-sprintf_%d_simple_quote.php","SQLi","RDF")
    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_int__multiple_AS-concatenation.php","SQLi","RDF")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-full_special_chars_filter__join-concatenation_simple_quote.php", "SQLi",
    #     "RDF")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__no_sanitizing__select_from_where-sprintf_%s_simple_quote.php",
    #     "SQLi",
    #     "RDF")

    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-sprintf_%d_simple_quote.php","SQLi","DT")
    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_int__multiple_AS-concatenation.php","SQLi","DT")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-full_special_chars_filter__join-concatenation_simple_quote.php", "SQLi",
    #     "DT")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__no_sanitizing__select_from_where-sprintf_%s_simple_quote.php",
    #     "SQLi",
    #     "DT")

    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-sprintf_%d_simple_quote.php","SQLi","SVM")
    # cmd_predict_file("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_int__multiple_AS-concatenation.php","SQLi","SVM")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-full_special_chars_filter__join-concatenation_simple_quote.php", "SQLi",
    #     "SVM")
    # cmd_predict_file(
    #     "data/SAMATE/Injection/CWE_89/unsafe/CWE_89__array-GET__no_sanitizing__select_from_where-sprintf_%s_simple_quote.php",
    #     "SQLi",
    #     "SVM")
    # cmd_predict_file("data/SAMATE/XSS/CWE_79/safe/CWE_79__array-GET__CAST-cast_float_sort_of__Use_untrusted_data_script-side_Quoted_Expr.php","SQLi","RDF")
    # cmd_predict_file(
    #     "data/SAMATE/XSS/CWE_79/unsafe/CWE_79__array-GET__func_addslashes__Use_untrusted_data_attribute-unquoted_Attr.php",
    #     "SQLi", "RDF")


if __name__ == "__main__":
    main()
