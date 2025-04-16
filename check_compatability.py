import csv

file = "report/compilation_results.csv"
total = 0
passed = 0

with open(file, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['Task'] == 'addition' and row['Technique'] == 'prompting':
            total += 1
            if row['Compiles'].strip().upper() == "YES":
                passed += 1

print(f"Pass@1 (Compilability) = {passed}/{total} = {passed / total:.2f}")