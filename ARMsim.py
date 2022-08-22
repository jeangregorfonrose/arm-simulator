# On  my  honor,  I  have  neither  given  nor  received unauthorized aid on this assignment2
import sys

# Processor Class
class Processor:
    def __init__(self) -> None:
        # Counter for Simulation
        self.cycle = 1
        self.program_counter = 64
        self.branch = 0

        # Data Storage needed for our program
        self.registers = [0 for number in range(32)]
        self.data = {}
        self.instructions = {}

        # Helper data
        self.instructions_set = {"001": {"10000": "CBZ", "10001": "CBNZ"}, "010": {"1000000": "ORRI", "1000001": "EORI", "1000010": "ADDI", "1000011": "SUBI", "1000100": "ANDI"}, "011": {"10100000": "EOR", "10100010": "ADD", "10100011": "SUB", "10100100": "AND", "10100101": "ORR", "10100110": "LSR", "10100111": "LSL"}, "100": {"10101010": "LDUR", "10101011": "STUR"}}
        self.instructions_opcode = {"001": 5, "010": 7, "011": 8, "100": 8}
        self.dummy_instruction = "10100000000000000000000000000000"
        self.dummy_inst_counter = 0

        # Files to write to
        self.assembly_filename = "disassembly.txt"
        self.simulation_filename = "simulation.txt"

        # Open all files that we need to use to output
        self.assembly_file = open(self.assembly_filename, "w")
        self.simulation_file = open(self.simulation_filename, "w")

    # -------------- Function of Category 4 ----------------- #
    # LDUR
    def ldur(self, srcdst, src1, imm_value):
        if(src1 == 31):
            self.registers[srcdst] = self.data[imm_value]
        else:
            self.registers[srcdst] = self.data[self.registers[src1]]

    # STUR
    def stur(self, srcdst, src1, imm_value):
        if(src1 != 31):
            self.data[self.registers[src1]] = self.registers[srcdst]
        else:
            self.data[imm_value] = self.registers[srcdst]

    # -------------- Function of Category 3 ----------------- #
    # EOR
    def eor(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] ^ self.registers[src2]

    # ADD
    def add(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] + self.registers[src2]

    # SUB
    def sub(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] - self.registers[src2]

    # AND
    def and_instr(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] & self.registers[src2]

    # ORR
    def orr(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] | self.registers[src2]

    # LSR
    def lsr(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] >> self.registers[src2]

    # LSL
    def lsl(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] << self.registers[src2]

    # -------------- Function of Category 2 ----------------- #
    # ORRI
    def orri(self, dest, src1, imm_value):
        self.registers[dest] = self.registers[src1] | imm_value

    # EORI
    def eori(self, dest, src1, imm_value):
        self.registers[dest] = self.registers[src1] ^ imm_value

    # ADDI
    def addi(self, dest, src1, imm_value):
        self.registers[dest] =  self.registers[src1] + imm_value

    # SUBI
    def subi(self, dest, src1, imm_value):
        self.registers[dest] = self.registers[src1] - imm_value

    # ANDI
    def andi(self, dest, src1, imm_value):
        self.registers[dest] = self.registers[src1] & imm_value

    # -------------- Function of Category 1 ----------------- #
    # CBZ
    def cbz(self, src1, branch_offset):
        if(self.registers[src1] == 0):
            self.branch = self.program_counter + (branch_offset * 4)
        else:
            self.branch = self.program_counter + 4

    # CBNZ
    def cbnz(self, src1, branch_offset):
        if(self.registers[src1] != 0):
            self.branch = self.program_counter + (branch_offset * 4)
        else:
            self.branch = self.program_counter + 4
    
    # ----------------- Helper Functions -------------------- #
    def twos_comp(self, val, bits):
        # compute the 2's complement of int value val
        if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
            val = val - (1 << bits)        # compute negative value
        return val

    # ---------------------- Files Functions -------------------------------- #
    # Write assembly equivalent of an instruction to a file
    def write_to_assembly_file(self, line):
        self.assembly_file.write(line + "\n")

    # Write the current state of the simulator in the simulation file
    def write_to_simulation_file(self):
        # Write the separators
        to_write = "--------------------\n"

        # Write the cycle, the pc counter and the instruction
        to_write += f"Cycle {self.cycle}:\t{self.program_counter}\t{self.instructions.get(self.program_counter)[1]}\n\n"

        # Write the registers and their values
        to_write += "Registers\n"
        for i in range(4):
            to_write += f"X{i*8:02d}:"
            for a in range(8):
                to_write += f"\t{self.registers[(i+a)+(i*7)]}"
            to_write += "\n"

        # Write the data object
        to_write += "\nData\n"
        pc_counter = self.dummy_inst_counter + 4
        while(self.data.get(pc_counter) != None):
            to_write += f"{pc_counter}:"
            counter = 0
            while(counter < 8 and self.data.get(pc_counter) != None):
                to_write += f"\t{self.data[pc_counter]}"
                pc_counter += 4
                counter += 1
            to_write += "\n"
        to_write += "\n"
        
        self.simulation_file.write(to_write)

    # CLose all files that were opened and in use
    def close_all_files(self):
        self.assembly_file.close()
        self.simulation_file.close()


    # ------------ Instructions Decoders and Executers Functions------------- #
    # Read the instructions, store them, and also get the data values as well
    def read_instruction(self, inst):
        # Clean the string for whitespace or new lines
        instruction = inst.strip()

        # define variable to use
        inst_pointer = 0
        assembly_inst = ""
        line_to_write = instruction + "\t" + str(self.program_counter) + "\t"

        # Get the first three digits to know which category it is
        first_three_digits = instruction[:3]

        # Add 3 to inst pointer since we got the first 3 bits
        inst_pointer += 3

        # Find which category they belong to
        category = self.instructions_set.get(first_three_digits)

        if(category != None):
            # get the opcode based on the category
            opcode = instruction[inst_pointer:(3 + self.instructions_opcode[first_three_digits])]
            
            # Increment inst_pointer to pass the opcode for next information to extract
            inst_pointer += self.instructions_opcode[first_three_digits]

            # Get the command associated to the opcode
            command = category.get(opcode)

            # Add command to the line to print
            assembly_inst += command + " "

            if(command != None):
                # Get the rest depend on the category
                if(first_three_digits == "001"):
                    # In the first category there is the src1(5 bits) and branch offset (19 bits)
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    #increment inst_pointer
                    inst_pointer += 5

                    # Get the Branch Offset (19 bits)
                    branch_offset_binary = instruction[inst_pointer:]

                    # Convert all values to decimal
                    src1 = self.twos_comp(int(src1_binary,2), len(src1_binary))
                    branch_offset = self.twos_comp(int(branch_offset_binary,2), len(branch_offset_binary))

                    assembly_inst += "X" + str(src1) + ", #" + str(branch_offset)
                elif(first_three_digits == "010"):
                    # Get the destination
                    destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]
                
                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the immediate_value
                    immediate_value_bin = instruction[inst_pointer:]

                    # Convert all values to decimal
                    destination = self.twos_comp(int(destination_bin,2), len(destination_bin))
                    src1 = int(src1_binary,2)
                    immediate_value = self.twos_comp(int(immediate_value_bin,2), len(immediate_value_bin))

                    assembly_inst += "X" + str(destination) + ", X" + str(src1) + ", #" + str(immediate_value)
                elif(first_three_digits == "011"):
                    # Get the destination
                    destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src2
                    src2_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    # Convert all values to decimal
                    destination = self.twos_comp(int(destination_bin,2), len(destination_bin))
                    src1 = self.twos_comp(int(src1_binary,2), len(src1_binary))
                    src2 = self.twos_comp(int(src2_binary,2), len(src2_binary))

                    assembly_inst += "X" + str(destination) + ", X" + str(src1) + ", X" + str(src2)
                elif(first_three_digits == "100"):
                    # Get the destination
                    src_destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]
                
                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the immediate_value
                    immediate_value_bin = instruction[inst_pointer:]

                    # Convert all values to decimal
                    src_destination = self.twos_comp(int(src_destination_bin,2), len(src_destination_bin))
                    src1 = int(src1_binary,2)

                    # check if src1 is 31 to change to XRZ
                    if(src1 == 31): src1 = "ZR"

                    immediate_value = self.twos_comp(int(immediate_value_bin,2), len(immediate_value_bin))

                    assembly_inst += "X" + str(src_destination) + ", [X" + str(src1) + ", #" + str(immediate_value) + "]"
                
                # Store instruction into isntruction along with PC counter and isntruction binary code
                self.instructions[self.program_counter] = [instruction, assembly_inst]

                # Add instruction to line_to_write
                line_to_write += assembly_inst
        else:
            if(instruction == self.dummy_instruction):
                line_to_write += "DUMMY"

                # Store the pc counter of dummy instruction
                self.dummy_inst_counter = self.program_counter

                # Store dummy instruction
                self.instructions[self.program_counter] = [instruction, "DUMMY"]

            else:
                # Convert number to decimal
                decimal = self.twos_comp(int(instruction,2), len(instruction))

                # Store the numbers in the data dictionary
                self.data[self.program_counter] = decimal

                line_to_write += str(decimal)

        self.write_to_assembly_file(line_to_write)
        # Increment PC counter
        self.program_counter += 4

    # Execute all the isntructions stored in the instructions list
    def exec_all_inst(self):
        # Reinitialize program counter to 64
        self.program_counter = 64

        # loop until program counter is not equal to dummy_inst_counter
        while(self.program_counter <= self.dummy_inst_counter):
            self.exec_instruction()
    
    # Execute an instruction
    def exec_instruction(self):
        # Clean the string for whitespace or new lines
        instruction = self.instructions.get(self.program_counter)[0].strip()

        # define variable to use
        inst_pointer = 0
        branch_function = False

        # Get the first three digits to know which category it is
        first_three_digits = instruction[:3]

        # Add 3 to inst pointer since we got the first 3 bits
        inst_pointer += 3

        # Find which category they belong to
        category = self.instructions_set.get(first_three_digits)

        if(category != None):
            # get the opcode based on the category
            opcode = instruction[inst_pointer:(3 + self.instructions_opcode[first_three_digits])]
            
            # Increment inst_pointer to pass the opcode for next information to extract
            inst_pointer += self.instructions_opcode[first_three_digits]

            # Get the command associated to the opcode
            command = category.get(opcode)

            if(command != None):
                # Get the rest depend on the category
                if(first_three_digits == "001"):
                    # In the first category there is the src1(5 bits) and branch offset (19 bits)
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    #increment inst_pointer
                    inst_pointer += 5

                    # Get the Branch Offset (19 bits)
                    branch_offset_binary = instruction[inst_pointer:]

                    # Convert all values to decimal
                    src1 = self.twos_comp(int(src1_binary,2), len(src1_binary))
                    branch_offset = self.twos_comp(int(branch_offset_binary,2), len(branch_offset_binary))

                    if(command == "CBZ"):
                        self.cbz(src1, branch_offset)
                    elif(command == "CBNZ"):
                        self.cbnz(src1, branch_offset)

                    # Change branch to True
                    branch_function = True

                elif(first_three_digits == "010"):
                    # Get the destination
                    destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]
                
                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the immediate_value
                    immediate_value_bin = instruction[inst_pointer:]

                    # Convert all values to decimal
                    destination = self.twos_comp(int(destination_bin,2), len(destination_bin))
                    src1 = int(src1_binary,2)
                    immediate_value = self.twos_comp(int(immediate_value_bin,2), len(immediate_value_bin))

                    if(command == "ORRI"):
                        self.orri(destination,src1, immediate_value)
                    elif(command == "EORI"):
                        self.eori(destination,src1, immediate_value)
                    elif(command == "ADDI"):
                        self.addi(destination,src1, immediate_value)
                    elif(command == "SUBI"):
                        self.subi(destination,src1, immediate_value)
                    elif(command == "ANDI"):
                        self.andi(destination,src1, immediate_value)

                elif(first_three_digits == "011"):
                    # Get the destination
                    destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src2
                    src2_binary = instruction[inst_pointer:(5 + inst_pointer)]

                    # Convert all values to decimal
                    destination = self.twos_comp(int(destination_bin,2), len(destination_bin))
                    src1 = self.twos_comp(int(src1_binary,2), len(src1_binary))
                    src2 = self.twos_comp(int(src2_binary,2), len(src2_binary))

                    if(command == "EOR"):
                        self.eor(destination, src1, src2)
                    elif(command == "ADD"):
                        self.add(destination, src1, src2)
                    elif(command == "SUB"):
                        self.sub(destination, src1, src2)
                    elif(command == "AND"):
                        self.and_instr(destination, src1, src2)
                    elif(command == "ORR"):
                        self.orr(destination, src1, src2)
                    elif(command == "LSR"):
                        self.lsr(destination, src1, src2)
                    elif(command == "LSL"):
                        self.lsl(destination, src1, src2)

                elif(first_three_digits == "100"):
                    # Get the destination
                    src_destination_bin = instruction[inst_pointer:(5 + inst_pointer)]

                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the src1
                    src1_binary = instruction[inst_pointer:(5 + inst_pointer)]
                
                    # Increment inst_pointer
                    inst_pointer += 5

                    # Get the immediate_value
                    immediate_value_bin = instruction[inst_pointer:]

                    # Convert all values to decimal
                    src_destination = self.twos_comp(int(src_destination_bin,2), len(src_destination_bin))
                    src1 = int(src1_binary,2)
                    immediate_value = self.twos_comp(int(immediate_value_bin,2), len(immediate_value_bin))

                    if(command == "LDUR"):
                        self.ldur(src_destination, src1, immediate_value)
                    elif (command == "STUR"):
                        self.stur(src_destination, src1, immediate_value)

        self.write_to_simulation_file()

        # Increment cycle
        self.cycle += 1
        
        # Check is no branch occured to know how to update pc counter
        if(branch_function):
            self.program_counter = self.branch
        else:
            self.program_counter += 4

# Get the filename from the arguments list
file_path = sys.argv[1]

# Hold the instructions read from the instructions' file
instructions = []

# Open file of the instructions
instructions_file = open(file_path, "r")

# Read file and save instructions
for line in instructions_file:
    instructions.append(line)

# Close instructions' file
instructions_file.close()

# Start Processor
processor = Processor()

# Make Processor read every instruction to store data
for instruction in instructions:
    processor.read_instruction(instruction)

# Make Processor executes all instructions
processor.exec_all_inst()

# Close all files of the processor
processor.close_all_files()