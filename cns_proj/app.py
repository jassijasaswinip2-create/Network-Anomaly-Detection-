from flask import Flask, render_template, request
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import os
from cryptography.fernet import Fernet  

app = Flask(__name__)
data = {
    'packet_size': [500, 520, 480, 510, 530, 490, 515, 505, 495, 525],
    'time_interval_ms': [10, 12, 11, 10, 13, 12, 11, 10, 12, 11],
    'protocol': [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    'flow_count': [5, 6, 5, 5, 6, 5, 5, 5, 6, 5]
}
df = pd.DataFrame(data)
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(df_scaled)
key_path = "secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
cipher = Fernet(key)
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/predict', methods=['POST'])
def predict():
    try:
        packet_size = float(request.form['packet_size'])
        time_interval = float(request.form['time_interval'])
        protocol = int(request.form['protocol'])
        flow_count = float(request.form['flow_count'])

        user_input = pd.DataFrame([[packet_size, time_interval, protocol, flow_count]],
                                  columns=['packet_size', 'time_interval_ms', 'protocol', 'flow_count'])
        user_scaled = scaler.transform(user_input)

        prediction = model.predict(user_scaled)[0]
        score = model.decision_function(user_scaled)[0]

        if prediction == -1:
            result = "⚠️ Anomaly Detected! Suspicious Network Activity."
            
            # Encrypt and save log securely
            log_data = f"Anomaly detected! Packet={packet_size}, Time={time_interval}, Protocol={protocol}, Flow={flow_count}, Score={score}"
            encrypted_log = cipher.encrypt(log_data.encode())

            with open("secure_logs.enc", "ab") as log_file:
                log_file.write(encrypted_log + b"\n")
        else:
            result = "✅ Normal Network Activity Detected."

        return render_template('index.html', result=result, score=round(score, 6))

    except Exception as e:
        return render_template('index.html', result=f"Error: {e}")
if __name__ == '__main__':
    app.run(debug=True)
