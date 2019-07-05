/*
View the internals of ELF object file

g++ -Wall -g -ggdb -Werror -std=c++11 -o elfview elfview.cpp
*/

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <elf.h>
#include <assert.h>
#include <type_traits>
#include <typeinfo>
#include <variant>
#include <iterator>
#include <algorithm>

#include "e_machine.h"

using namespace std;

template<typename T>
class HexFormat
{
    /* Custom hex stream manipulator to add '0x' prefix
    for an unsigned char type hexadecimal representation */
public:
    HexFormat(const T& c) : value(c) {}
    ostream& operator()(ostream& out) const
    {
        ostringstream hex_string;
        hex_string << "0x" << hex << value;
        out << hex_string.str();

        return out;
    } 

private:
    T value;
};

template<typename T>
HexFormat<T> hf(const T& c)
{
    return HexFormat<T>(c);
}

template<typename T>
ostream& operator<<(ostream& out, HexFormat<T> c2hex)
{
    return c2hex(out);
}

string to_str(const vector<string>& table, vector<string>::size_type index,
              const string& default_value)
{
    if (index < table.size())
    {
        return table[index];
    }

    return default_value;
}

class fbackup
{
    public:
        fbackup(ifstream& file) : file_(file)
        {
            current_ = file_.tellg();
        }

        ~fbackup()
        {
            if (file_.tellg() != current_)
            {
                file_.seekg(current_, file_.beg);
            }
        }

    private:
        ifstream& file_;
        streampos current_;
};

int get_object_class(ifstream& file)
{
    fbackup _(file);
    file.seekg(EI_CLASS, file.beg);
    
    return file.get(); 
}

template<typename Elf_Ehdr>
class MainHeader
{
    public:
        MainHeader(ifstream& file) : file_(file) {}

        void view()
        {
            parse(header_);
            print(header_);
        }

        operator Elf_Ehdr()
        {
            return header_;
        }

    private:
        void parse(Elf_Ehdr& header)
        {
            file_.seekg(0, file_.beg);
            file_.read(reinterpret_cast<char*>(&header), sizeof(Elf_Ehdr));
        }

        void print(const Elf_Ehdr& header)
        {
            print_e_ident(header.e_ident);

            vector<string> e_type {
                /* ET_NONE */ "No file type",
                /* ET_REL */ "Relocatable file",
                /* ET_EXEC */ "Executable file",
                /* ET_DYN */ "Shared object file",
                /* ET_CORE */ "Core file",
                /* ET_LOPROC */ "Processor-specific",
                /* ET_HIPROC */ "Processor-specific"
            };

            vector<string> e_version {
                /* EV_NONE */ "Invalid version",
                /* EV_CURRENT */ "Current version"
            };

            cout << "e_type (object file type): " << hf(header.e_type) << " ("
                << to_str(e_type, header.e_type, "Unknown 'e_type' field")
                << ")" << endl;
            cout << "e_machine (architecture): " << hf(header.e_machine) << " ("
                << get_machine_description(header.e_machine) << ")" << endl;
            cout << "e_version (object file version): " << hf(header.e_version) << " ("
                << to_str(e_version, header.e_version, "Unknown 'e_version' field")
                << ")" << endl;
            // TODO: show more information about the EP, like name of section, maybe disassembled commands, etc.
            cout << "e_entry (entry point): " << hf(header.e_entry) << endl;
            cout << "e_phoff (program header table): " << hf(header.e_phoff) << endl;
            cout << "e_shoff (section header table): " << hf(header.e_shoff) << endl;
            cout << "e_flags (processor specific flags): " << hf(header.e_flags) << endl;
            cout << "e_ehsize (ELF header size): " << header.e_ehsize << endl;
            cout << "e_phentsize (program header entry size): " << header.e_phentsize << endl;
            cout << "e_phnum (number of entries in program header): " << header.e_phnum << endl;
            cout << "e_shentsize (section header size): " << header.e_shentsize << endl;
            cout << "e_shnum (number of entries in section header): " << header.e_shnum << endl;
            cout << "e_shstrndx (index of section string table): " << header.e_shstrndx << endl;

        }

        void print_e_ident(const unsigned char e_ident[EI_NIDENT])
        {
            vector<string> ei_class {
                /* ELFCLASSNONE */ "Invalid class",
                /* ELFCLASS32 */ "32-bit objects",
                /* ELFCLASS64 */ "64-bit objects"
            };

            vector<string> data_encoding {
                /* ELFDATANONE */ "Invalid data encoding",
                /* ELFDATA2LSB */ "Little-endian",
                /* ELFDATA2MSB */ "Big-endian"
            };

            vector<string> version {
                /* EV_NONE */ "Invalid version",
                /* EV_CURRENT */ "Current version"
            };

            cout << "[ELF Header]" << endl;
            cout << "e_ident:" << endl;
            cout << "\tFile identification [" << EI_MAG0 << "] = " << hf(unsigned(e_ident[EI_MAG0])) << endl;
            cout << "\tFile identification [" << EI_MAG1 << "] = " << "'" << e_ident[EI_MAG1] << "'" << endl;
            cout << "\tFile identification [" << EI_MAG2 << "] = " << "'" << e_ident[EI_MAG2] << "'" << endl;
            cout << "\tFile identification [" << EI_MAG3 << "] = " << "'" << e_ident[EI_MAG3] << "'" << endl;
            cout << "\tFile class [" << EI_CLASS << "] = " << hf(unsigned(e_ident[EI_CLASS]))
                << " (" << to_str(ei_class, e_ident[EI_CLASS], "Unknown 'EI_CLASS' field") << ")"
                << endl;
            cout << "\tData encoding [" << EI_DATA << "] = " << hf(unsigned(e_ident[EI_DATA])) 
                << " ("
                << to_str(data_encoding, e_ident[EI_DATA], "Unknown 'EI_DATA' field")
                << ")"
                << endl;
            cout << "\tELF header version number [" << EI_VERSION << "] = "
                << hf(unsigned(e_ident[EI_VERSION])) << " ("
                << to_str(version, e_ident[EI_VERSION], "Unknown 'EI_VERSION' field")
                << ")"
                << endl;
            cout << "\tPadding bytes: ";
            
            for (unsigned int i = EI_PAD; i < EI_NIDENT; i++)
            {
                cout << hf(unsigned(e_ident[i])) << " ";
            }
            cout << endl;
        }
    
    private:
        ifstream& file_;
        Elf_Ehdr header_;
};

template<typename Elf_Ehdr,typename Elf_Shdr>
class SectionHeader
{
    public:
        SectionHeader(ifstream& file, Elf_Ehdr main_header) : file_(file),
            main_header_(main_header) {}
        
        void view()
        {
            parse(main_header_);
            print();
        }
    
    private:
        void parse(const Elf_Ehdr& main_header)
        {
            file_.seekg(main_header.e_shoff, file_.beg);

            // extract all sections header
            for (uint16_t i = 0; i < main_header.e_shnum; i++)
            {
                Elf_Shdr section_header;
                file_.read(reinterpret_cast<char*>(&section_header), sizeof(Elf_Shdr));
                sections_header_.push_back(section_header);
            }

            // read the string table
            if (SHN_UNDEF != main_header.e_shstrndx &&
                main_header.e_shstrndx < sections_header_.size())
            {
                const Elf_Shdr& string_section_header = sections_header_[main_header.e_shstrndx];
                file_.seekg(string_section_header.sh_offset, file_.beg);
                string_table_.resize(string_section_header.sh_size);
                file_.read(&string_table_[0], string_section_header.sh_size);
            }
        }

        void print()
        {
            cout << "[Sections (" << sections_header_.size() << ")]" << endl;
            for (uint32_t i = 0; i < sections_header_.size(); i++)
            {
                cout << "Section " << i << endl;

                print(sections_header_[i]);
            }
        }

        void print(const Elf_Shdr& header)
        {
            string section_name = get_section_name(header.sh_name);
            section_name = section_name.empty() ? "No Name" : section_name;

            cout << "sh_name (section name): " << section_name << endl;
        }

        string get_section_name(const uint32_t index)
        {
            const char delimiter = '\0';
            string name;
            
            if (index < string_table_.size())
            {
                auto start = string_table_.begin();
                advance(start, index);
                auto pos = find(start, string_table_.end(), delimiter);
                if (pos != end(string_table_))
                {
                    copy(start, pos, back_inserter(name));
                }
            }

            return name;
        }

    private:
        ifstream& file_;
        Elf_Ehdr main_header_;
        vector<char> string_table_;
        vector<Elf_Shdr> sections_header_;
};

template<typename Elf_Ehdr, typename Elf_Shdr>
class ELFView
{
    public:
        ELFView(ifstream& file) : file_(file)
        {}

        void view()
        {
            MainHeader<Elf_Ehdr> mh(file_);
            mh.view();
            cout << endl;
            SectionHeader<Elf_Ehdr,Elf_Shdr> sh(file_, mh);
            sh.view();
            cout << endl;
        }
    private:
        ifstream& file_;
};

void view(ifstream& file)
{
    int object_class = get_object_class(file);
    if (object_class == ELFCLASS32)
    {
        ELFView<Elf32_Ehdr,Elf32_Shdr> viewer(file);
        viewer.view();
    }
    else if (object_class == ELFCLASS64)
    {
        ELFView<Elf64_Ehdr,Elf64_Shdr> viewer(file);
        viewer.view();
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        cout << "The input file is not specified." << endl;
        cout << "Usage: elf_parser file.out" << endl;
    }
    else
    {
        ifstream file(argv[1], ifstream::in|ifstream::binary|ifstream::ate);
        if (file && file.tellg() > 0)
        {
            view(file);
        }
        else
        {
            cout << "Can't open " << argv[1]
                 << " file, check file permissions or file size (non-empty)" << endl;
        }
    }

    return 0;
}