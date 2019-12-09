import xml.etree.ElementTree as ET
import fileinput
import sys
from numpy import binary_repr

variables = {}
stack = []


def main():
    root = ET.parse('/tmp/output_simulator.xml').getroot()
    functions = {}
    for function in root.findall("function"):
        iv_varnodes = {}
        outputs = []
        insns = []
        for instruction in function.find("instructions"):
            pcodes = []
            for pcode in instruction.find("pcodes"):
                output = pcode.find("output")
                if output is not None:
                    output_varnode = Varnode(output.text, int(output.get("size")), 0)
                    outputs.append(output.text)
                else:
                    output_varnode = None
                inputs = []
                for input_node in pcode.find("inputs"):
                    if input_node.get("storage") == "constant":
                        variables[input_node.text] = Varnode(input_node.text, int(input_node.get("size"), 0), int(input_node.text, 16))
                        inputs.append(variables[input_node.text])
                    else:
                        inputs.append(Varnode(input_node.text, int(input_node.get("size")), 0))
                        if input_node.text not in outputs:
                            iv_varnodes[input_node.text] = Varnode(input_node.text, int(input_node.get("size"), 0), 0)
                pc = Pcode(pcode.find("name").text, inputs, output_varnode)
                pcodes.append(pc)
            insn = Instruction(instruction.text, pcodes)
            insns.append(insn)
        fn = Function(insns, iv_varnodes)
        functions[function.get("name")] = fn

    print("Function List: ")
    for fn in list(functions.keys()):
        print("--->" + fn)

    selection = ""
    while selection not in list(functions.keys()):
        selection = input("Enter function you'd like to execute: ")
    functions[selection].execute_function()


def print_state():
    for key in list(variables.keys()):
        if "0x" not in key:
            print(key + " = " + str(variables[key].value) + ", binary = " + str(binary_repr(variables[key].value, variables[key].size*8)))



class Function:
    def __init__(self, instructions, iv_varnodes):
        self.instructions = instructions
        self.iv_varnodes = iv_varnodes

    def execute_function(self):
        print("The following variables need to be initialized: ")
        for var in list(self.iv_varnodes.keys()):
            value = input("Please provide an initial value for " + var + ":")
            self.iv_varnodes[var].set_value(int(value, 0))
            variables[var] = self.iv_varnodes[var]
        for instruction in self.instructions:
            instruction.execute_instruction()


class Instruction:
    def __init__(self, text, pcodes):
        self.text = text
        self.pcodes = pcodes

    def execute_instruction(self):
        selection = ""
        while selection not in ["n", "p"]:
            selection = input("Press [n] for next instruction, [p] for next pcode, [s] for machine state")
            if selection is "s":
                print_state()
        print(self.text)
        if selection is "n":
            for pcode in self.pcodes:
                pcode.populate()
                pcode.execute_pcode()
        elif selection is "p":
            for pcode in self.pcodes:
                pcode.populates()
                pcode.execute_pcode()
                while selection not in ["n", "p"]:
                    selection = input("Press [n] for next instruction, [p] for next pcode, [s] for machine state")
                    if selection is "s":
                        print_state()
                if selection is "n":
                    skip = True
        elif selection is "s":
            print_state()


class Pcode:
    def __init__(self, mnemonic, inputs, output):
        self.mnemonic = mnemonic
        self.inputs = inputs
        self.output = output
        self.string = None

    def populate(self):
        if self.output is not None:
            string = self.output.name + " = " + self.mnemonic + " "
        else:
            string = self.mnemonic + " "
        for i in range(len(self.inputs)):
            input_string = self.inputs[i]
            if i == len(self.inputs)-1:
                string = string + input_string.name
            else:
                string = string + input_string.name + ", "
        self.string = string

    def execute_pcode(self):
        print("--->" + self.string)
        if self.string == "COPY":
            pass
        elif self.mnemonic == "LOAD":
            pass
        elif self.mnemonic == "STORE":
            pass
        elif self.mnemonic == "BRANCH":
            pass
        elif self.mnemonic == "CBRANCH":
            pass
        elif self.mnemonic == "BRANCHIND":
            pass
        elif self.mnemonic == "CALL":
            pass
        elif self.mnemonic == "CALLIND":
            pass
        elif self.mnemonic == "USERDEFINED":
            pass
        elif self.mnemonic == "RETURN":
            pass
        elif self.mnemonic == "PIECE":
            pass
        elif self.mnemonic == "SUBPIECE":
            source_size = variables[self.inputs[0].name].size*8
            throwaway_size = variables[self.inputs[1].name].value*8
            source = binary_repr(variables[self.inputs[0].name].value, source_size)
            if throwaway_size != 0:
                pass
            else:
                result = int(source[self.output.size*8:], 2)
            self.output.set_value(result)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_EQUAL":
            pass
        elif self.mnemonic == "INT_NOTEQUAL":
            pass
        elif self.mnemonic == "INT_LESS":
            if self.inputs[0].value < self.inputs[1].value:
                less = 1
            else:
                less = 0
            self.output.set_value(less)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SLESS":
            if self.inputs[0].value < self.inputs[1].value:
                less = 1
            else:
                less = 0
            self.output.set_value(less)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_LESSEQUAL":
            pass
        elif self.mnemonic == "INT_SLESSEQUAL":
            pass
        elif self.mnemonic == "INT_ZEXT":
            self.output.set_value(variables[self.inputs[0].name].value)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SEXT":
            pass
        elif self.mnemonic == "INT_ADD":
            result = int(variables[self.inputs[0].name].value) + int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SUB":
            result = int(variables[self.inputs[0].name].value) - int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_CARRY":
            result = int(variables[self.inputs[0].name].value) + int(variables[self.inputs[1].name].value)
            if result >= 2**(self.inputs[0].size*8 + 1):
                carry = 1
            else:
                carry = 0
            self.output.set_value(carry)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SCARRY":
            result = int(variables[self.inputs[0].name].value) + int(variables[self.inputs[1].name].value)
            if result >= 2 ** (self.inputs[0].size * 8 + 1):
                carry = 1
            else:
                carry = 0
            self.output.set_value(carry)
            variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SBORROW":
            pass
        elif self.mnemonic == "INT_2COMP":
            pass
        elif self.mnemonic == "INT_NEGATE":
            pass
        elif self.mnemonic == "INT_XOR":
            result = int(variables[self.inputs[0].name].value) ^ int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_AND":
            result = int(variables[self.inputs[0].name].value) & int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_OR":
            result = int(variables[self.inputs[0].name].value) | int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_LEFT":
            result = int(variables[self.inputs[0].name].value) << int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_RIGHT":
            result = int(variables[self.inputs[0].name].value) >> int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SRIGHT":
            result = int(variables[self.inputs[0].name].value) >> int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_MULT":
            result = int(variables[self.inputs[0].name].value) * int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_DIV":
            result = int(variables[self.inputs[0].name].value) / int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_REM":
            result = int(variables[self.inputs[0].name].value) % int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SDIV":
            result = int(variables[self.inputs[0].name].value) / int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "INT_SREM":
            result = int(variables[self.inputs[0].name].value) % int(variables[self.inputs[1].name].value)
            if self.output.name in list(variables.keys()):
                variables[self.output.name].set_value(result)
            else:
                self.output.set_value(result)
                variables[self.output.name] = self.output
        elif self.mnemonic == "BOOL_NEGATE":
            pass
        elif self.mnemonic == "BOOL_XOR":
            pass
        elif self.mnemonic == "BOOL_AND":
            pass
        elif self.mnemonic == "BOOL_OR":
            pass
        elif self.mnemonic == "FLOAT_EQUAL":
            pass
        elif self.mnemonic == "FLOAT_NOTEQUAL":
            pass
        elif self.mnemonic == "FLOAT_LESS":
            pass
        elif self.mnemonic == "FLOAT_LESSEQUAL":
            pass
        elif self.mnemonic == "FLOAT_ADD":
            pass
        elif self.mnemonic == "FLOAT_SUB":
            pass
        elif self.mnemonic == "FLOAT_MULT":
            pass
        elif self.mnemonic == "FLOAT_DIV":
            pass
        elif self.mnemonic == "FLOAT_NEG":
            pass
        elif self.mnemonic == "FLOAT_ABS":
            pass
        elif self.mnemonic == "FLOAT_SQRT":
            pass
        elif self.mnemonic == "FLOAT_CEIL":
            pass
        elif self.mnemonic == "FLOAT_FLOOR":
            pass
        elif self.mnemonic == "FLOAT_ROUND":
            pass
        elif self.mnemonic == "FLOAT_NAN":
            pass
        elif self.mnemonic == "INT2FLOAT":
            pass
        elif self.mnemonic == "FLOAT2FLOAT":
            pass
        elif self.mnemonic == "TRUNC":
            pass
        elif self.mnemonic == "CPOOLREF":
            pass
        elif self.mnemonic == "NEW":
            pass
        elif self.mnemonic == "MULTIEQUAL":
            pass
        elif self.mnemonic == "INDIRECT":
            pass
        elif self.mnemonic == "PTRADD":
            pass
        elif self.mnemonic == "PTRSUB":
            pass
        elif self.mnemonic == "CAST":
            pass
        else:
            raise Exception("Not a standard pcode instruction")


class Varnode:
    def __init__(self, name, size, value):
        self.name = name
        self.size = size
        self.value = value

    def set_value(self, value):
        self.value = value


if __name__ == "__main__":
    main()