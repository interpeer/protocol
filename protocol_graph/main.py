# -*- coding: utf-8 -*-
################################################################################
#                    ____            _                  _                      #
#                   |  _ \ _ __ ___ | |_ ___   ___ ___ | |                     #
#                   | |_) | '__/ _ \| __/ _ \ / __/ _ \| |                     #
#                   |  __/| | | (_) | || (_) | (_| (_) | |                     #
#                   |_|   |_|  \___/ \__\___/ \___\___/|_|                     #
#                                                                              #
#           == A Simple ASCII Header Generator for Network Protocols ==        #
#                                                                              #
################################################################################
#                                                                              #
#  Written by:                                                                 #
#                                                                              #
#     Luis MartinGarcia.                                                       #
#       -> E-Mail: luis.mgarc@gmail.com                                        #
#       -> WWWW:   http://www.luismg.com                                       #
#       -> GitHub: https://github.com/luismartingarcia                         #
#                                                                              #
################################################################################
#                                                                              #
#  This file is part of Protocol.                                              #
#                                                                              #
#  Copyright (C) 2014 Luis MartinGarcia (luis.mgarc@gmail.com)                 #
#                                                                              #
#  This program is free software: you can redistribute it and/or modify        #
#  it under the terms of the GNU General Public License as published by        #
#  the Free Software Foundation, either version 3 of the License, or           #
#  (at your option) any later version.                                         #
#                                                                              #
#  This program is distributed in the hope that it will be useful,             #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of              #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
#  GNU General Public License for more details.                                #
#                                                                              #
#  You should have received a copy of the GNU General Public License           #
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                              #
#  Please check file LICENSE.txt for the complete version of the license,      #
#  as this disclaimer does not contain the full information. Also, note        #
#  that although Protocol is licensed under the GNU GPL v3 license, it may     #
#  be possible to obtain copies of it under different, less restrictive,       #
#  alternative licenses. Requests will be studied on a case by case basis.     #
#  If you wish to obtain Protocol under a different license, please contact    #
#  the email address mentioned above.                                          #
#                                                                              #
################################################################################
#                                                                              #
# Description:                                                                 #
#                                                                              #
#  Protocol is a command-line tool that provides quick access to the most      #
#  common network protocol headers in ASCII (RFC-like) format. It also has the #
#  ability to create ASCII headers for custom protocols defined by the user    #
#  through a very simple syntax.                                               #
#                                                                              #
################################################################################

# INTERNAL IMPORTS
from protocol_graph.constants import *
from protocol_graph.exceptions import *
from protocol_graph import Protocol

class Main():
    """
    This class does all the boring task of a command-line application. It parses
    user input, displays usage, parses input files, etc.
    """

    def __init__(self):
        """
        Class constructor. Nothing fancy.
        """
        self.cmd_line_args=None             # Copy of the user argv
        self.protocols=[]                   # List of protocols to print out
        self.bits_per_line=None             # Number of bits per line to print
        self.skip_numbers=None              # True to avoid printing bit units and tens
        self.hdr_char_start=None            # Character for start of the border line
        self.hdr_char_end=None              # Character for end of the border line
        self.hdr_char_fill_odd=None         # Fill character for border odd positions
        self.hdr_char_fill_even=None        # Fill character for border even positions
        self.hdr_char_sep=None              # Field separator character
        self.do_left_to_right_print=True    # Filed Print From Left To Right
        self.ph_num_per_bit=1               # PlaceHold Number Per Bits


    def display_help(self):
        """
        Displays command-line usage help to standard output.
        """
        print("")
        print("%s v%s" % (APPLICATION_NAME, APPLICATION_VERSION))
        print("Copyright (C) %i, %s (%s)." % (max(2014, date.today().year), APPLICATION_AUTHOR, APPLICATION_AUTHOR_EMAIL))
        print("This software comes with ABSOLUTELY NO WARRANTY.")
        print("")
        self.display_usage()
        print("PARAMETERS:")
        print(" <protocol>              : Name of an existing protocol")
        print(" <spec>                  : Field by field specification of non-existing protocol")
        print("OPTIONS:")
        print(" -b, --bits <n>          : Number of bits per line")
        print("-ph","--placeholder <n>  : Number of placeholder unit per bit")
        print(" -f, --file              : Read specs from a text file")
        print(" -lsb                    : Print Field From Lsb to Msb")
        print(" -h, --help              : Displays this help information")
        print(" -n, --no-numbers        : Do not print bit numbers on top of the header")
        print(" -V, --version           : Displays current version")
        print(" --evenchar  <char>      : Character for the even positions of horizontal table borders")
        print(" --oddchar   <char>      : Character for the odd positions of horizontal table borders")
        print(" --startchar <char>      : Character that starts horizontal table borders")
        print(" --endchar   <char>      : Character that ends horizontal table borders")
        print(" --sepchar   <char>      : Character that separates protocol fields")


    def get_usage(self):
        """
        @return a string containing application usage information
        """
        return "Usage: %s {<protocol> or <spec>} [OPTIONS]" % self.cmd_line_args[0]


    def display_usage(self):
        """
        Prints usage information to standard output
        """
        print(self.get_usage())


    def parse_config_file(self, filename):
        """
        This method parses the supplied configuration file and adds any protocols to our
        list of protocols to print.
        @return The number of protocols parsed
        """

        i=0
        # Read the contents of the whole file
        try:
            f = open(filename)
            lines = f.readlines()
            f.close()
        except:
            print("Error while reading file %s. Please make sure it exists and it's readable." % filename)
            sys.exit(1)

        # Parse protocol specs, line by line
        for line in lines:
            # Sanitize the line
            line=line.strip()

            # If it starts with #, or is an empty line ignore it
            if line.startswith("#") or len(line)==0:
                continue

            # If we have something else, treat it as a protocol spec
            proto=Protocol(line)
            self.protocols.append(proto)
            i+=1

        return i


    def parse_cmd_line_args(self, argv, is_config_file=False):
        """
        Parses command-line arguments and stores any relevant information
        internally
        """
        import sys

        # Store a reference to command line args for later use.
        if is_config_file==False:
            self.cmd_line_args = argv

        # Check we have received enough command-line parameters
        if len(argv) == 1 and is_config_file is False:
            print(self.get_usage())
            sys.exit(1)
        else:
            skip_arg=False
            for i in range(1, len(argv)):

                # Useful for args like -c <filename>. This avoids parsing the
                # filename as it if was a command-line flag.
                if skip_arg==True:
                    skip_arg=False
                    continue

                # Spec file
                if argv[i]=="-f" or argv[i]=="--file":
                    # Make sure we have an actual parameter after the flag
                    if (i+1)>=len(argv):
                        return OP_FAILURE, "Expected parameter after %s\n%s" % (argv[i], self.get_usage())
                    skip_arg=True
                    # Parse the config file
                    protos = self.parse_config_file(argv[i+1])
                    if protos <= 0:
                        return OP_FAILURE, "No protocol specifications found in the supplied file (%s)" % argv[i+1]
                
                if argv[i]=="-ph" or argv[i]=="--placeholder":
                    # Make sure we have an actual parameter after the flag
                    if (i+1)>=len(argv):
                        return OP_FAILURE, "Expected parameter after %s\n%s" % (argv[i], self.get_usage())
                    skip_arg=True
                    # Parse the config file
                    try:
                        self.ph_num_per_bit=int(argv[i+1])
                        if self.ph_num_per_bit<=0:
                            return OP_FAILURE, "Invalid number of placeholder unit per line supplied (%s)" % argv[i+1]
                    except:
                        return OP_FAILURE, "Invalid number of placeholder unit per line supplied (%s)" % argv[i+1]

                # Bits per line
                elif argv[i]=="-b" or argv[i]=="--bits":
                    # Make sure we have an actual parameter after the flag
                    if (i+1)>=len(argv):
                        return OP_FAILURE, "Expected parameter after %s\n%s" % (argv[i], self.get_usage())
                    skip_arg=True
                    # Parse the config file
                    try:
                        self.bits_per_line=int(argv[i+1])
                        if self.bits_per_line<=0:
                            return OP_FAILURE, "Invalid number of bits per line supplied (%s)" % argv[i+1]
                    except:
                        return OP_FAILURE, "Invalid number of bits per line supplied (%s)" % argv[i+1]

                # Avoid displaying numbers on top of the header
                elif argv[i]=="-n" or argv[i]=="--no-numbers":
                    self.skip_numbers=True

                # Character variations
                elif argv[i] in ["--oddchar", "--evenchar", "--startchar", "--endchar", "--sepchar"]:
                    # Make sure we have an actual parameter after the flag
                    if (i+1)>=len(argv):
                        return OP_FAILURE, "Expected parameter after %s\n%s" % (argv[i], self.get_usage())
                    skip_arg=True

                    # Make sure we got a single character, not more
                    if len(argv[i+1])!=1:
                        return OP_FAILURE, "A single character is expected after %s\n%s" % (argv[i], self.get_usage())

                    # Now let's store whatever character spec we got
                    if argv[i]=="--oddchar":
                        self.hdr_char_fill_odd=argv[i+1]
                    elif argv[i]=="--evenchar":
                        self.hdr_char_fill_even=argv[i+1]
                    elif argv[i]=="--startchar":
                        self.hdr_char_start=argv[i+1]
                    elif argv[i]=="--endchar":
                        self.hdr_char_end=argv[i+1]
                    elif argv[i]=="--sepchar":
                        self.hdr_char_sep=argv[i+1]

                # print field from left to right
                elif argv[i]=="-lsb":
                        self.do_left_to_right_print=False
                # Display help
                elif argv[i]=="-h" or argv[i]=="--help":
                    self.display_help()
                    sys.exit(0)

                # Display version
                elif argv[i]=="-V" or argv[i]=="--version":
                    print("%s v%s" % (APPLICATION_NAME, APPLICATION_VERSION))
                    sys.exit(0)

                # Incorrect option supplied
                elif argv[i].startswith("-"):
                    print("ERROR: Invalid option supplied (%s)" % argv[i])
                    sys.exit(1)

                # Protocol name or protocol spec
                else:
                    # If it contains ":" characters, we have a protocol spec
                    if argv[i].count(":")>0:
                        spec = argv[i]
                    # Otherwise, the user meant to display an existing protocol
                    else:
                        # If we got an exact match, end of story
                        if argv[i] in specs.protocols:
                            spec = specs.protocols[argv[i]]
                        # Otherwise, we may have received a partial match so
                        # we need to figure out which protocol the user meant.
                        # If the specification is ambiguous, we will error
                        else:
                            start_with_the_same=[]
                            for spec in specs.protocols:
                                if spec.startswith(argv[i]):
                                    start_with_the_same.append(spec)
                            # If we only have one entry, it means we got some
                            # shortened version of the protocol name but no
                            # ambiguity. In that case, we will use the match.
                            if len(start_with_the_same)==1:
                                spec=specs.protocols[start_with_the_same[0]]
                            elif len(start_with_the_same)==0:
                                print("ERROR: supplied protocol '%s' does not exist." % argv[i]);
                                sys.exit(1)
                            else:
                                print("Ambiguous protocol specifier '%s'. Did you mean any of these?" % argv[i])
                                for spec in start_with_the_same:
                                    print("  %s" % spec)
                                sys.exit(1)
                    # Finally, based on the spec, instance an actual protocol.
                    # Note that if the spec is incorrect, the Protocol() constructor
                    # will call sys.exit() itself, so there is no need to do
                    # error checking here.
                    try:
                        proto = Protocol(spec)
                        self.protocols.append(proto)
                    except ProtocolException as e:
                        print("ERROR: %s" % str(e))
                        sys.exit(1)

        if len(self.protocols)==0:
            print("ERROR: Missing protocol")
            sys.exit(1)

        return OP_SUCCESS, None



    def run(self):
        """
        This is Protocol's 'core' method: parses command line argument and prints
        any necessary protocol to standard output
        """
        import sys

        # Parse command-line arguments
        code, err = self.parse_cmd_line_args(sys.argv)
        if code!=OP_SUCCESS:
            print("ERROR: %s" % err)
            sys.exit(1)

        # Print the appropriate protocol headers
        for i in range(0, len(self.protocols)):

            # Modify the properties of the object if the user passed any
            # options that require it
            if self.bits_per_line is not None:
                self.protocols[i].bits_per_line = self.bits_per_line
            if self.skip_numbers is not None:
                if self.skip_numbers is True:
                    self.protocols[i].do_print_top_tens=False
                    self.protocols[i].do_print_top_units=False
                else:
                    self.protocols[i].do_print_top_tens=True
                    self.protocols[i].do_print_top_units=True
            if self.hdr_char_end is not None:
                self.protocols[i].hdr_char_end=self.hdr_char_end
            if self.hdr_char_start is not None:
                self.protocols[i].hdr_char_start=self.hdr_char_start
            if self.hdr_char_fill_even is not None:
                self.protocols[i].hdr_char_fill_even=self.hdr_char_fill_even
            if self.hdr_char_fill_odd is not None:
                self.protocols[i].hdr_char_fill_odd=self.hdr_char_fill_odd
            if self.hdr_char_sep is not None:
                self.protocols[i].hdr_char_sep=self.hdr_char_sep
            self.protocols[i].do_left_to_right_print=self.do_left_to_right_print
            self.protocols[i].ph_num_per_bit=self.ph_num_per_bit

            print(self.protocols[i])
            if len(self.protocols)>1 and i!=len(self.protocols)-1:
                print("")


# Main function
def main():
    """
    Main function. Runs the Protocol program.
    """

    # Instance our core class
    program = Main()

    # Do our magic
    program.run()


# THIS IS THE START OF THE EXECUTION
if __name__ == "__main__":
    main()
