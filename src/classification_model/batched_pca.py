from sklearn.decomposition import IncrementalPCA


class BatchedPCA:
    def __init__(self, n_components):
        # self.all_features = all_features

        self.ipca = IncrementalPCA(n_components=n_components)

    def partial_fit(self, X, y=None):
        # for col in self.all_features:
        #     if col not in X:
        #         X[col] = 0

        self.ipca.partial_fit(X, y)

    def transform(self, X, y=None):
        # for col in self.all_features:
        #     if col not in X:
        #         X[col] = 0

        return self.ipca.transform(X)

