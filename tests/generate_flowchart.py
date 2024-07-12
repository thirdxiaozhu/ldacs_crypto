import os
import sys
import re
from graphviz import Digraph

class FlowchartGenerator:
    def __init__(self):
        self.graph = Digraph(comment='C Code Flowchart')
        self.node_id = 0

    def new_node(self, label):
        node_name = 'node{}'.format(self.node_id)
        self.graph.node(node_name, label)
        self.node_id += 1
        return node_name

    def add_edge(self, src, dst):
        self.graph.edge(src, dst)

    def parse_c_code(self, file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        functions = {}
        current_function = None
        function_body = []

        for line in lines:
            line = line.strip()
            if line.startswith('//') or line.startswith('#'):
                continue
            # Check for function definitions
            if re.match(r'\w+\s+\w+\s*\(.*\)\s*{', line):
                if current_function:
                    functions[current_function] = function_body
                    function_body = []
                current_function = line
            if current_function:
                function_body.append(line)
            if line == '}':
                functions[current_function] = function_body
                current_function = None
                function_body = []

        return functions

    def generate_flowchart(self, functions):
        for func, body in functions.items():
            func_name = re.findall(r'\w+\s+(\w+)\s*\(', func)[0]
            start_node = self.new_node('Start: {}'.format(func_name))
            prev_node = start_node

            for line in body:
                if line == '{' or line == '}':
                    continue
                stmt_node = self.new_node(line)
                self.add_edge(prev_node, stmt_node)
                prev_node = stmt_node

            end_node = self.new_node('End: {}'.format(func_name))
            self.add_edge(prev_node, end_node)

        return self.graph

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_flowchart.py <C_SOURCE_FILE>")
        sys.exit(1)

    c_file = sys.argv[1]
    generator = FlowchartGenerator()
    functions = generator.parse_c_code(c_file)
    graph = generator.generate_flowchart(functions)
    graph.render('flowchart', format='png', cleanup=True)
    print('Flowchart generated: flowchart.png')