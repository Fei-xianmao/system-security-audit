"""
Risk Scoring Module
"""

class RiskScorer:
    WEIGHTS = {
        'CRITICAL': 20,
        'HIGH': 10,
        'MEDIUM': 5,
        'LOW': 1,
    }

    MAX_SCORE = 100

    def score(self, findings):
        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            f['risk_score'] = self.WEIGHTS.get(sev, 5)
        return findings

    def assign_priority(self, findings):
        """按严重性排序发现"""
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda f: severity_order.get(f.get('severity', 'MEDIUM'), 2))
        return findings

    def calculate_score(self, findings):
        total_deduction = sum(self.WEIGHTS.get(f.get('severity', 'MEDIUM'), 5) for f in findings)
        return max(0, self.MAX_SCORE - total_deduction)

    @staticmethod
    def severity_counts(findings):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            if sev in counts:
                counts[sev] += 1
        return counts
