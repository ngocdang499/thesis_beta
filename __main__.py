import json
import pickle

import numpy as np

from src.utils.logs import *
from src.dataset.dataset_factory import *
from src.utils.tools import gen_ast_img

from src.feature_generation.feature_generation import *
from src.classification_model.batched_pca import *
from src.feature_generation.gSpan.gspan_mining.gspan import gSpan

from src.classification_model.train import *


def cmd_create_set():
    print_banner("Build sets")
    global sets
    sel_ds = get_str('dataset', 'SelectedDataset')
    sets = get_dataset(sel_ds).get_sets()


def cmd_gen_ast_img(filepath):
    gen_ast_img(filepath)


def cmd_create_CPG(set_type, language, vuln_type):
    print_banner("Generate CPGs and import to database")
    for filepath in sets[set_type][language][vuln_type]:
        print(vuln_type)
        CSVGraph.generate_CPG(filepath, vuln_type, sets['flaw_dict'][language][vuln_type][filepath])


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
    print(gs.result)
    return gs.result.copy()

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


def write_patterns_to_file(patterns_set):
    patterns_file = get_str("processed_files", "PatternsFile")
    with open(patterns_file, 'a') as f:
        for pattern in patterns_set:
            f.write(json.dumps(pattern)+"\n")


def cmd_read_patterns_from_file():
    patterns_file = get_str("processed_files", "PatternsFile")
    if os.path.isfile(patterns_file):
        patterns_set = []
        with open(patterns_file, 'r') as f:
            lines = f.readlines()
            for l in lines:
                # print(l)
                patterns_set.append(json.loads(l))
        return patterns_set
    else:
        print_warning("Unable to read patterns from file. File does not exist.")
        return None


def cmd_train_model(pca=None):
    print_banner(f'Train classifier model')

    dataset_file = get_str("processed_files", "FeaturesFile")
    dataset = pd.read_csv(dataset_file, header=None)

    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values

    if pca:
        X = pca.transform(X,y)

    print(len(y))
    #
    # from sklearn.model_selection import train_test_split
    # X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Building and training the model
    classifier = select_model("XSS", X, y)

    print("y test",np.count_nonzero(y))
    # Predicting the Test set results
    y_pred = classifier.predict(X)
    # print(y_pred, y_test[4])

    # # Making the Confusion Matrix
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y, y_pred)
    print(cm)

    # Generating accuracy, precision, recall and f1-score
    from sklearn.metrics import classification_report
    target_names = ['Safe', 'XSS']
    print(classification_report(y, y_pred, target_names=target_names))

    return classifier


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


def cmd_generate_feature_vector(filename):
    print_banner(f'Generate feature vector')

    import_graph_to_neo4j(filename)
    features = cmd_read_patterns_from_file()

    return generate_features_from_code(features)


def cmd_predict_file(filepath, vuln_type, model_name, display_ast=False):
    print_banner(f'Predict {vuln_type} in file with {model_name}')

    dataset_file = get_str("processed_files", "FeaturesFile")
    dataset = pd.read_csv(dataset_file, header=None)

    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values

    pca = BatchedPCA(30)
    pca.partial_fit(X, y)

    feature_vector = np.array(cmd_generate_feature_vector(filepath))
    print("Feature", feature_vector[84])
    feature_vector = [feature_vector]

    feature_vector = pca.transform(feature_vector)
    classifier = cmd_load_model(vuln_type, model_name)

    res = classifier.predict(feature_vector)
    print(res)


def main():
    init("config.ini")
    # cmd_create_set()
    # cmd_create_CPG('tuning_set', 'PHP', 'XSS')
    # print_banner("Mine Safe")
    # patterns = cmd_mine_frequent_pattern(0.5, 0.5, "Safe_XSS")
    # print(len(patterns))
    # print_banner("Mine Unsafe")
    # patterns = patterns + cmd_mine_frequent_pattern(0.6, 0.5, "XSS")
    # print(len(patterns))
    # print_banner("Mine Other")
    # patterns = patterns + cmd_mine_frequent_pattern(0.8, 0.2, "XSS", 2)
    # print(len(patterns))
    # # print_banner("Result patterns")
    # write_patterns_to_file(patterns)


    # generate_features_from_code(patterns)
    # print(patterns)
    # pt = cmd_read_patterns_from_file()
    # # # #
    # create_features_file(pt, CSVGraph.getCPGsByType("XSS", "testing_set") , "XSS")
    # create_features_file(pt, CSVGraph.getCPGsByType("Safe_XSS", "testing_set"), "XSS")
    # create_features_file(pt, CSVGraph.getCPGsByType("Safe_SQLi", "tuning_set"), "XSS")
    # create_features_file(pt, CSVGraph.getCPGsByType("SQLi", "tuning_set"), "XSS")

    dataset_file = get_str("processed_files", "FeaturesFile")
    dataset = pd.read_csv(dataset_file, header=None)

    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values

    pca = BatchedPCA(30)
    pca.partial_fit(X,y)

    print("vuln", np.count_nonzero(y))

    model = cmd_train_model(pca)
    cmd_save_model("XSS", "RDF", model)
    # generate_features_from_code(pt)
    # print(pt)
    # if pt:
    #     print("here")
    #     create_features_file(pt)
    # cmd_gen_ast_img("data/SAMATE/Injection/CWE_89/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-concatenation.php")
    # import_graph_to_neo4j("test.php")


    # dataset_file = get_str("processed_files", "FeaturesFile")
    # dataset = pd.read_csv(dataset_file, header=None)
    #
    # X = dataset.iloc[:, :-1].values
    # y = dataset.iloc[:, -1].values
    #
    # pca = BatchedPCA(30)
    # pca.partial_fit(X,y)
    #
    # X = pca.transform(X)
    # model = cmd_load_model("SQLi", "DT")
    #
    # y_pred = model.predict(X)
    # from sklearn.metrics import confusion_matrix
    # cm = confusion_matrix(y, y_pred)
    # print(cm)
    # #
    # # # Generating accuracy, precision, recall and f1-score
    # from sklearn.metrics import classification_report
    # target_names = ['Safe', 'SQLi']
    # print(classification_report(y, y_pred, target_names=target_names))

    # cmd_predict_file("test.php","SQLi","RDF")

if __name__ == "__main__":
    main()
