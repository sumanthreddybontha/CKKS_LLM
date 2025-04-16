# import csv

# # Optional: define expected output values for specific files
# expected_outputs = {
#     "addition": "Encrypted sum is",  # rough matching
#     "multiplication": "Encrypted product is",
#     "dot_product": "Dot product is",
# }

# pass_count = 0
# total = 0

# with open("report/compilation_results.csv") as f:
#     reader = csv.DictReader(f)
#     for row in reader:
#         if row["Runs"] == "YES":
#             total += 1
#             task = row["Task"]
#             if expected_outputs[task].lower() in row["Output"].lower():
#                 pass_count += 1

# print(f"Pass@1 functionality: {pass_count}/{total} = {pass_count/total:.2f}")

import csv

file = "report/compilation_results.csv"
total = 0
passed = 0

with open(file, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['Task'] == 'addition' and row['Technique'] == 'prompting':
            if row['Compiles'].strip().upper() == "YES":
                total += 1
                if "sum" in row['Output'].lower() or "result" in row['Output'].lower():
                    passed += 1

print(f"Pass@1 (Functionality) = {passed}/{total} = {passed / total:.2f}")
