import math


class MmrFeatureSelection(object):
    """`MMRFS` algorithm."""

    def __init__(self,
                 population):
        """Initialize MMRFA instance."""
        self.population = population


    @staticmethod
    def entropy(support):
        """Calculate entropy."""
        c1 = support[0]
        c2 = support[1]
        total = c1 + c2

        etp = - (c1/total)*math.log2(c1/total) - (c2/total)*math.log2(c2/total)
        return etp

    def information_gain(self, pattern_support):
        """Calculate information gain of a pattern."""
        parent_etp = MmrFeatureSelection.entropy(self.population)
        total = sum(self.population)

        c1_etp = MmrFeatureSelection.entropy(pattern_support)
        total1 = sum(pattern_support)

        pattern_unsupport = [self.population[0] - pattern_support[0], self.population[1] - pattern_support[1]]
        c2_etp = MmrFeatureSelection.entropy(pattern_unsupport)
        total2 = sum(pattern_unsupport)

        return parent_etp - (total1/total * c1_etp + total2/total * c2_etp)

    def relevance(self, pattern_support, measurement='IG'):
        """Calculate relevance of a pattern."""
        rel = 0
        if measurement == 'Fisher':
            rel = self.information_gain(pattern_support)
        else:
            rel = self.information_gain(pattern_support)
        return rel

    def redundancy(self, pattern1, pattern2):
        pass
