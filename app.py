from flask import Flask, render_template, request, redirect, flash
import pymysql
import csv
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Database connection details
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='r4ve',
        password='123',
        database='cve_db'
    )

@app.route('/')
def index():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SHOW COLUMNS FROM cves")
        columns = cursor.fetchall()
        cursor.execute("SELECT * FROM cves")
        cves = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('index.html', cves=cves, columns=columns)
    except Exception as e:
        flash(f"Error loading data: {str(e)}", 'error')
        return render_template('index.html', cves=[], columns=[])

@app.route('/add', methods=['POST'])
def add_cve():
    cve_id = request.form['cve_id']
    rule_name = request.form['rule_name']
    cve_description = request.form['cve_description']
    severity = request.form['severity']
    correlation_logic = request.form['correlation_logic']
    created_by = request.form['created_by']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cves (cve_id, rule_name, cve_description, severity, correlation_logic, created_by) VALUES (%s, %s, %s, %s, %s, %s)",
                       (cve_id, rule_name, cve_description, severity, correlation_logic, created_by))
        conn.commit()
        cursor.close()
        conn.close()
        flash('CVE added successfully!', 'success')
    except Exception as e:
        flash(f"Error adding CVE: {str(e)}", 'error')

    return redirect('/')

@app.route('/edit/<cve_id>', methods=['GET', 'POST'])
def edit_cve(cve_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM cves WHERE cve_id = %s", (cve_id,))
        cve = cursor.fetchone()

        if request.method == 'POST':
            rule_name = request.form['rule_name']
            cve_description = request.form['cve_description']
            severity = request.form['severity']
            correlation_logic = request.form['correlation_logic']
            created_by = request.form['created_by']

            cursor.execute("""
                UPDATE cves SET rule_name = %s, cve_description = %s, severity = %s, correlation_logic = %s, created_by = %s
                WHERE cve_id = %s
            """, (rule_name, cve_description, severity, correlation_logic, created_by, cve_id))
            conn.commit()

            flash('CVE updated successfully!', 'success')
            return redirect('/')
        cursor.close()
        conn.close()
        return render_template('edit.html', cve=cve)
    except Exception as e:
        flash(f"Error editing CVE: {str(e)}", 'error')
        return redirect('/')

@app.route('/export', methods=['GET'])
def export_csv():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM cves")
        cves = cursor.fetchall()

        with open('cve_export.csv', 'w', newline='') as csvfile:
            fieldnames = cves[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(cves)

        cursor.close()
        conn.close()
        flash('CSV exported successfully!', 'success')
    except Exception as e:
        flash(f"Error exporting CSV: {str(e)}", 'error')

    return redirect('/')

@app.route('/export_sql', methods=['GET'])
def export_sql():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cves")
        cves = cursor.fetchall()

        with open('cve_export.sql', 'w') as sqlfile:
            for cve in cves:
                columns = ['cve_id', 'rule_name', 'cve_description', 'severity', 'correlation_logic', 'created_by', 'created_at']
                sqlfile.write(f"INSERT INTO cves ({', '.join(columns)}) VALUES ({', '.join([f'{value}' for value in cve])});\n")

        cursor.close()
        conn.close()
        flash('SQL exported successfully!', 'success')
    except Exception as e:
        flash(f"Error exporting SQL: {str(e)}", 'error')

    return redirect('/')

@app.route('/add_column', methods=['GET', 'POST'])
def add_column():
    if request.method == 'POST':
        column_name = request.form['column_name']
        data_type = request.form['data_type']
        data_size = request.form['data_size']
        column_definition = f"{column_name} {data_type}({data_size})"

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(f"ALTER TABLE cves ADD COLUMN {column_definition}")
            conn.commit()
            cursor.close()
            conn.close()
            flash(f'Column {column_name} added successfully!', 'success')
        except Exception as e:
            flash(f"Error adding column: {str(e)}", 'error')

        return redirect('/add_column')

    return render_template('add_column.html')

if __name__ == '__main__':
    app.run(debug=True)
