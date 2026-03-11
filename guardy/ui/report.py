from typing import List, Dict, Any

class UserReportGenerator:
    @staticmethod
    def generate_report(user_id: str, historical_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Takes raw history data retrieved by the backend DB and formats it into a security report.
        """
        total_uploads = len(historical_records)
        flagged_uploads = sum(1 for rec in historical_records if not rec.get("is_safe", True))
        
        avg_risk = 0.0
        if total_uploads > 0:
            avg_risk = sum(rec.get("risk_score", 0.0) for rec in historical_records) / total_uploads
            
        is_risky_user = avg_risk > 0.4 or flagged_uploads > 2
        
        return {
            "user_id": user_id,
            "total_uploads": total_uploads,
            "blocked_uploads": flagged_uploads,
            "average_risk_score": round(avg_risk, 2),
            "status": "FLAGGED" if is_risky_user else "SAFE",
            "recommendation": "Review recent uploads" if is_risky_user else "No action required"
        }
