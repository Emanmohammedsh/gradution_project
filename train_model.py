import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import pickle

data = pd.read_csv("training_data.csv")

data["exploit_type"] = data["exploit_type"].map({
    "metasploit": 3,
    "hydra": 2,
    "web": 1,
    "manual": 0
})

data["priority_label"] = data["priority_label"].map({
    "high": 2,
    "medium": 1,
    "low": 0
})

X = data[["cvss_score", "exploit_type", "port"]]
y = data["priority_label"]

model = DecisionTreeClassifier()
model.fit(X, y)

with open("exploit_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved!")