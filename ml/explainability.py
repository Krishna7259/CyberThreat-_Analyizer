import numpy as np
import pandas as pd
import shap
from ml.preprocessing import clean_and_prepare_df, ALL_FEATURE_COLUMNS

class CyberShieldExplainer:
    def __init__(self, model, preprocessor):
        self.model = model
        self.preprocessor = preprocessor
        # Build TreeExplainer for the Random Forest classifier
        try:
            self.explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            print(f"[!] Warning: SHAP TreeExplainer initialization failed: {e}")
            self.explainer = None

    def explain_instance(self, event_dict: dict, top_k=6):
        """
        Calculates feature attributions for a single security event record.
        Returns top features, shap values, and plain-language summary.
        """
        try:
            # Create a single-row DataFrame
            df = pd.DataFrame([event_dict])
            df_clean = clean_and_prepare_df(df)
            
            # Transform via pipeline
            X_trans = self.preprocessor.transform(df_clean)
            
            # Get transformed feature names
            try:
                feature_names = self.preprocessor.get_feature_names_out()
            except Exception:
                feature_names = [f"feature_{i}" for i in range(X_trans.shape[1])]

            # Predict probabilities
            probs = self.model.predict_proba(X_trans)[0]
            threat_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            pred_class = "Suspicious" if threat_prob >= 0.5 else "Normal"

            contributions = []

            if self.explainer is not None:
                shap_values = self.explainer.shap_values(X_trans)
                
                # For binary classification: shap_values can be a list of 2 arrays [class_0, class_1]
                # or a 3D array (n_samples, n_features, n_classes) depending on shap version
                if isinstance(shap_values, list) and len(shap_values) >= 2:
                    vals = shap_values[1][0]  # Attributions for Class 1 (Attack/Suspicious)
                elif hasattr(shap_values, 'shape') and len(shap_values.shape) == 3:
                    vals = shap_values[0, :, 1]
                elif hasattr(shap_values, 'shape') and len(shap_values.shape) == 2:
                    vals = shap_values[0]
                else:
                    vals = np.array(shap_values)[0]

                # Pair feature name with contribution
                for name, val, raw_val in zip(feature_names, vals, X_trans[0]):
                    # Clean feature name display (e.g. 'num__sbytes' -> 'sbytes')
                    clean_name = name.split('__')[-1]
                    contributions.append({
                        'feature': clean_name,
                        'contribution': float(round(val, 4)),
                        'raw_transformed_value': float(round(raw_val, 4)),
                        'impact': 'Increases Risk' if val > 0 else 'Reduces Risk'
                    })
                
                # Sort by absolute magnitude of contribution
                contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
                top_contributions = contributions[:top_k]
            else:
                # Fallback to feature importance weights
                importances = getattr(self.model, 'feature_importances_', [])
                for name, imp, raw_val in zip(feature_names, importances, X_trans[0]):
                    clean_name = name.split('__')[-1]
                    contributions.append({
                        'feature': clean_name,
                        'contribution': float(round(imp, 4)),
                        'raw_transformed_value': float(round(raw_val, 4)),
                        'impact': 'Dominant Classifier Weight'
                    })
                contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
                top_contributions = contributions[:top_k]

            # Generate natural language summary
            top_factors = [f"{c['feature']} ({c['impact']})" for c in top_contributions[:3]]
            if pred_class == "Suspicious":
                narrative = (
                    f"The machine learning model classified this event as Suspicious with "
                    f"{threat_prob * 100:.1f}% confidence. The primary contributing factors "
                    f"were: {', '.join(top_factors)}."
                )
            else:
                narrative = (
                    f"The machine learning model classified this event as Normal with "
                    f"{(1.0 - threat_prob) * 100:.1f}% confidence. Normal characteristics "
                    f"in {', '.join(top_factors)} lowered the threat probability."
                )

            return {
                'success': True,
                'predicted_class': pred_class,
                'threat_probability': round(threat_prob, 4),
                'top_contributions': top_contributions,
                'explanation_text': narrative
            }

        except Exception as ex:
            return {
                'success': False,
                'error': str(ex),
                'predicted_class': 'Unknown',
                'threat_probability': 0.0,
                'top_contributions': [],
                'explanation_text': f"Explanation computation unavailable: {str(ex)}"
            }
