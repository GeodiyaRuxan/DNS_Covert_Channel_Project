from flask import Flask, render_template_string
import sqlite3

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SOC Dashboard</title>

    <meta http-equiv="refresh" content="5">

    <style>
        body {
            background-color: #071330;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }

        h1 {
            color: white;
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #0b1d46;
        }

        th {
            background-color: #102a63;
            color: white;
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #1f3c88;
        }

        td {
            padding: 10px;
            border-bottom: 1px solid #1f3c88;
        }

        tr:hover {
            background-color: #132f6b;
        }

        .high {
            color: red;
            font-weight: bold;
        }

        .medium {
            color: orange;
            font-weight: bold;
        }

        .low {
            color: lightgreen;
            font-weight: bold;
        }

        .card-container {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }

        .card {
            background-color: #102a63;
            padding: 20px;
            border-radius: 10px;
            width: 220px;
            box-shadow: 0 0 10px rgba(0,0,0,0.4);
        }

        .card h2 {
            margin: 0;
            font-size: 18px;
        }

        .card p {
            font-size: 28px;
            margin-top: 10px;
        }
    </style>
</head>

<body>

    <h1>SOC Dashboard</h1>

    <div class="card-container">

        <div class="card">
            <h2>DNS Tunneling</h2>
            <p>{{ dns_tunnel }}</p>
        </div>

        <div class="card">
            <h2>DNS Exfiltration</h2>
            <p>{{ dns_exfil }}</p>
        </div>

        <div class="card">
            <h2>ICMP Alerts</h2>
            <p>{{ icmp }}</p>
        </div>

        <div class="card">
            <h2>TCP Alerts</h2>
            <p>{{ tcp }}</p>
        </div>

    </div>

    <table>

        <tr>
            <th>Time</th>
            <th>Src</th>
            <th>Dst</th>
            <th>Protocol</th>
            <th>Domain</th>
            <th>Size</th>
            <th>Attack</th>
            <th>Category</th>
            <th>Suspicion</th>
        </tr>

        {% for row in rows %}
        <tr>

            <td>{{ row[0] }}</td>
            <td>{{ row[1] }}</td>
            <td>{{ row[2] }}</td>
            <td>{{ row[3] }}</td>
            <td>{{ row[4] }}</td>
            <td>{{ row[5] }}</td>
            <td>{{ row[6] }}</td>
            <td>{{ row[7] }}</td>

            {% if row[8] == "High" %}
                <td class="high">{{ row[8] }}</td>

            {% elif row[8] == "Medium" %}
                <td class="medium">{{ row[8] }}</td>

            {% else %}
                <td class="low">{{ row[8] }}</td>

            {% endif %}

        </tr>
        {% endfor %}

    </table>

</body>
</html>
"""

@app.route('/')

def dashboard():

    conn = sqlite3.connect("soc.db")
    cursor = conn.cursor()

    # Get logs
    cursor.execute("SELECT * FROM logs ORDER BY time DESC")
    rows = cursor.fetchall()

    # Statistics
    cursor.execute("SELECT COUNT(*) FROM logs WHERE attack='DNS Tunneling'")
    dns_tunnel = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE attack='DNS Exfiltration'")
    dns_exfil = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE protocol='ICMP'")
    icmp = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE protocol='TCP'")
    tcp = cursor.fetchone()[0]

    conn.close()

    return render_template_string(
        HTML,
        rows=rows,
        dns_tunnel=dns_tunnel,
        dns_exfil=dns_exfil,
        icmp=icmp,
        tcp=tcp
    )

if __name__ == "__main__":
    app.run(debug=True)
