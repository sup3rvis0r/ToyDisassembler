#nullable enable
namespace ToyDisassembler
{
    using System;
    using System.Linq;
    using Iced.Intel;
    using PeNet;
    using PeNet.Structures;

    public class PeDisassembler
    {
        public PeDisassembler(byte[] peFile)
        {
            this.PeRawBytes = peFile;
            this.PeFile = new PeFile(this.PeRawBytes);
            this.CodeReader = new ByteArrayCodeReader(this.PeRawBytes);

            var startOffset = this.FindEntryPointOffset();
            Console.WriteLine($"Found Entry Point Offset: 0x{startOffset:X}");

            this.CodeReader.Position = startOffset;

            this.Instructions = new InstructionList();
            this.Decoder = Decoder.Create(this.PeFile.Is64Bit ? 64 : 32, this.CodeReader);

            this.CalculateIp();
        }

        public byte[] PeRawBytes { get; }
        public PeFile PeFile { get; set; }
        public ByteArrayCodeReader CodeReader { get; }

        public InstructionList Instructions { get; }

        public Decoder Decoder { get; }

        private void CalculateIp()
        {
            var ip = this.PeFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint +
                     this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase;
            //+ this.PeFile.ImageRelocationDirectory[0].TypeOffsets[1]
            //    .Offset; // TODO Reverse these blackmagic indexes

            this.Decoder.IP = ip;

            Console.WriteLine($"Calculated Start VirtAddr 0x{ip:X}");
        }

        private int FindEntryPointOffset()
        {
            var ep = this.PeFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
            Console.WriteLine($"AddressOfEntryPoint 0x{ep:X}");
            // Find section header where ep virtual address is located
            var section = this.PeFile.ImageSectionHeaders.First(x => AddressIsInSection(ep, x));

            return (int) (ep + section.PointerToRawData - section.VirtualAddress);
        }

        private static bool AddressIsInSection(uint address, IMAGE_SECTION_HEADER header)
        {
            return header.VirtualAddress <= address && address <= header.VirtualAddress + header.VirtualSize;
        }

        private void Disassemble()
        {
            while (true)
            {
                this.Decoder.Decode(out var instruction);
                this.Instructions.Add(instruction);

                Console.ResetColor();

                // After decoding, analyze the instruction
                Console.WriteLine($"[0x{this.Decoder.IP - (ulong) instruction.ByteLength:X}] {instruction}");
                Console.ForegroundColor = ConsoleColor.Cyan;

                // We do not know what is code, and what is data. We need to follow all jcc's and calls
                // and disassemble the code there.

                if (instruction.FlowControl != FlowControl.Next)
                {
                    Console.WriteLine($"[Flow Control Change] Type -> {instruction.FlowControl}");

                    // Get new addr
                    var target = instruction.NearBranchTarget;
                    Console.WriteLine($"[Flow Control Change] Target -> 0x{target:X}");

                    // Convert target to offset
                    var offset = this.ConvertVirtAddrToBinOffset(target);
                    Console.WriteLine($"[Flow Control Change] PE Offset -> 0x{offset:X}");

                    // todo support branching calls
                    if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                    {
                        Console.WriteLine("[Flow Control Change] [Unconditional Branch] Followed jmp, disassembling.");
                        this.Decoder.IP = target;
                        this.CodeReader.Position = (int) offset;
                    }
                }

                Console.ReadKey();
            }
        }

        private ulong ConvertVirtAddrToBinOffset(in ulong target)
        {
            // Virt Addr = Offset – Section_RawOffset + Section_VirtualAddress + ImageBase
            // VirtAddr + section_rawOffset - section va - image base = offset

            // Find the section this virtual addr is in
            var address = target - this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase;
            //- this.PeFile.ImageRelocationDirectory[0].TypeOffsets[1].Offset;

            var section = this.PeFile.ImageSectionHeaders.First(x => AddressIsInSection((uint) address, x));

            return address + section.PointerToRawData - section.VirtualAddress;
        }

        public void StartDisassembly()
        {
            this.Disassemble();
        }
    }
}