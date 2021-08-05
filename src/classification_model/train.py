import operator
import os

import itertools
from sklearn import svm
from sklearn import tree
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB
from sklearn.tree import DecisionTreeClassifier

from . import metrics
from src.utils.config import *
from src.utils.logs import print_notice, print_error


hyperparameters = {'DecisionTreeClassifier':
                       {'max_depth': [5, 15, 30, None],
                        'min_samples_leaf': [1, 2, 10, 50, 100],
                        'max_features': ['log2', 'sqrt', None],
                        'n_jobs': [-1],
                        'class_weight': ['balanced']},
                   'RandomForestClassifier':
                       {'n_estimators': [300, 500],
                        'max_depth': [5, 15, 30, None],
                        'min_samples_leaf': [1, 2, 10],
                        'max_features': ['log2', 'sqrt'],
                        'class_weight': ['balanced'],
                        'n_jobs': [-1]
                        },
                   'SVM':
                       {'C': [0.01, 0.1, 1, 10, 100],
                        'gamma': [0.0005, 0.05, 0.5, 5, 50, 500, 'auto'],
                        'kernel': ['poly'],
                        'probability': [True],
                        'shrinking': [False],
                        'class_weight': ['balanced']
                        }
                   }


def create_model(model_type, params):
    model = None

    if model_type == "DT":
        model = DecisionTreeClassifier()
    elif model_type == "RDF":
        model = RandomForestClassifier()
    elif model_type == "SVM":
        model = svm.SVC()

    if params is not None:
        for parameter, value in params.items():
            setattr(model, parameter, value)

    if model_type == "SVM":
        n_estimators = 10

        # Because SVM is so slow, we use a bagging classifier to speed things up
        model = BaggingClassifier(model, max_samples=1.0 / n_estimators, n_estimators=n_estimators, n_jobs=4)

    return model


def select_model(vuln_type, model_type, X, Y):
    params = get_dict('model', model_type + vuln_type + 'Params', optional=True)
    model = create_model(model_type, params)

    model.fit(X, Y)

    if model_type == "DT" and get_boolean('model', 'GenerateDecisionTreeGraph'):
        create_dt_graph("%s_%s" % (vuln_type), model, X.columns.values)

    # X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
    # select_best_model(X_train, y_train, X_test, y_test)
    return model


def select_best_model(X, Y, X_tuning, Y_tuning, model_type):
    best_model_i = -1
    best_auc_pr = -1

    combinations = get_hyperparameter_combinations(model_type)

    for i in range(len(combinations)):

        print_notice("Generating model %d / %d with parameters: %s" % (1 + i, len(combinations), str(combinations[i])))

        model = create_model(model_type, combinations[i])

        model.fit(X, Y)

        probas = model.predict_proba(X_tuning)

        _, _, auc_pr = metrics.get_auc_score(Y_tuning, probas)

        print_notice("Model %d has AUC-PR %.2f" % (1 + i, auc_pr))

        if auc_pr > best_auc_pr:
            best_model_i = i
            best_auc_pr = auc_pr

    print_notice("Model %d generated best AUC-PR (%.2f) with parameters: %s" % (1 + best_model_i, best_auc_pr,
                                                                                str(combinations[best_model_i])))


def get_hyperparameter_combinations(model_type):
    value_lists = []
    parameters = []
    combinations = []

    for parameter, values in hyperparameters[model_type].items():
        parameters.append(parameter)

        value_lists.append(values)

    # Get cartesian product of the hyperparameter values
    for element in itertools.product(*value_lists):
        combo = dict()

        for i in range(len(element)):
            combo[parameters[i]] = element[i]

        combinations.append(combo)

    return combinations


def select_features(X, Y):
    k = get_int('model', 'kFeatures')

    print_notice("Sorting features based on chi^2 (k=%d):" % k)

    if k < 0 or k > len(X.columns):
        print_error("k should be >= 0 and <= %d (n_features). Got %d." % (len(X.columns), k))
        exit(-1)

    skb = SelectKBest(chi2, k=k)
    skb.fit_transform(X, Y)

    support = skb.get_support()

    n = 1
    features = dict()

    for col_name, score in zip(X.columns.values[support], skb.scores_[support]):
        features[col_name] = score

    for feature, score in sorted(features.items(), key=operator.itemgetter(1), reverse=True):
        print_notice("%d. %s %.2f" % (n, feature, score))
        n += 1

    return X.columns.values[support]


def create_dt_graph(title, model, features):
    graph_dir = config.get_str('model', 'DecisionTreeGraphDirectory')

    dot_file = os.path.join(graph_dir, '%s.dot' % title)
    png_file = os.path.join(graph_dir, '%s.png' % title)

    print_notice("Creating Decision Tree graph in %s" % png_file)

    # Write DOT file
    tree.export_graphviz(model, out_file=dot_file, feature_names=features, filled=True, rounded=True, proportion=True,
                         node_ids=True)

    # Convert DOT to PNG
    os.system("dot -Tpng %s >%s" % (dot_file, png_file))

