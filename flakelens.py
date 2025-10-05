import re
from sqlglot import parse_one, exp

panel_queries = []

with open("Input\JSON_model.txt", "r", encoding="utf-8") as f:

    for line in f:
        l = line.strip()
        if l.startswith('"rawSql"'):
            unescaped = l.encode().decode('unicode_escape')
            cleaned_string = unescaped.replace('\n', ' ').replace('\t', ' ').replace('--', ' ')
            cleaned_string = re.sub(r'\s+', ' ', cleaned_string).strip()
            panel_queries.append(cleaned_string[11:-2])
            
panel_number = 0

for panel_query in panel_queries:
    try:
        panel_number += 1
        panel_query = re.sub(r"\$__\w+\([^\)]*\)", "1=1", panel_query)
        panel_query = re.sub(r"\$\{?\w+\}?", "1=1", panel_query)
        tree = parse_one(panel_query, read='snowflake')
        tables = {table.name for table in tree.find_all(exp.Table)}
        print(f"Tables in query for panel {panel_number}: {tables}")
    except Exception as e:
        print(f"Failed to parse: {panel_query}\nError: {e}")