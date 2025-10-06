#!/usr/bin/env python3
# Quick script to fix the syntax error in visualize_policy_graph.py

with open('tools/visualize_policy_graph.py', 'r') as f:
    content = f.read()

# Fix the incomplete print statement
content = content.replace('print(".2f"', 'print(".2f")')

with open('tools/visualize_policy_graph.py', 'w') as f:
    f.write(content)

print("Fixed syntax error in visualize_policy_graph.py")
