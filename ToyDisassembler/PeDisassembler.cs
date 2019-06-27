#nullable enable
namespace ToyDisassembler
{
    using System;
    using System.Collections.Generic;
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
            this.Instructions = new InstructionList();
            this.Decoder = Decoder.Create(this.PeFile.Is64Bit ? 64 : 32, this.CodeReader);
        }

        public byte[] PeRawBytes { get; }
        public PeFile PeFile { get; set; }
        public ByteArrayCodeReader CodeReader { get; }

        public InstructionList Instructions { get; }

        public Decoder Decoder { get; }

        public HashSet<ulong> VisitedAddresses { get; } = new HashSet<ulong>();
        public Queue<ulong> AddressesToAnalyze { get; } = new Queue<ulong>();

        private ulong CalculateIp()
        {
            var ip = this.PeFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint +
                     this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase;

            Console.WriteLine($"Calculated Start VirtAddr 0x{ip:X}");

            return ip;
        }

        private static bool AddressIsInSection(uint address, IMAGE_SECTION_HEADER header)
        {
            return header.VirtualAddress <= address && address <= header.VirtualAddress + header.VirtualSize;
        }

        private void Disassemble()
        {
            while (this.AddressesToAnalyze.Count > 0)
            {
                var virtAddr = this.AddressesToAnalyze.Dequeue();
                this.ChangeInstructionPointer(virtAddr);

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"Now disassembling 0x{virtAddr:X}");

                while (true)
                {
                    this.Decoder.Decode(out var instr);
                    this.Instructions.Add(instr);

                    Console.ResetColor();
                    Console.WriteLine($"[0x:{instr.IP:X}] {instr}");
                    Console.ForegroundColor = ConsoleColor.Cyan;

                    if (instr.FlowControl == FlowControl.Next || instr.FlowControl == FlowControl.Interrupt)
                    {
                        continue;
                    }

                    if (instr.FlowControl == FlowControl.Return || instr.FlowControl == FlowControl.IndirectBranch ||
                        instr.FlowControl == FlowControl.IndirectCall)
                    {
                        break;
                    }

                    var targetVirtAddr = instr.NearBranchTarget;

                    if (this.VisitedAddresses.Contains(targetVirtAddr))
                    {
                        break;
                    }

                    this.VisitedAddresses.Add(targetVirtAddr);

                    if (instr.FlowControl == FlowControl.UnconditionalBranch)
                    {
                        this.ChangeInstructionPointer(targetVirtAddr);
                        continue;
                    }

                    Console.WriteLine($"Enqueueing 0x{targetVirtAddr:X}");
                    this.AddressesToAnalyze.Enqueue(targetVirtAddr);
                }
            }
        }

        private void ChangeInstructionPointer(ulong virtAddr)
        {
            this.Decoder.IP = virtAddr;
            this.CodeReader.Position = (int) this.ConvertVirtAddrToBinOffset(virtAddr);
            this.VisitedAddresses.Add(virtAddr);
        }

        private ulong ConvertVirtAddrToBinOffset(in ulong target)
        {
            // Virt Addr = Offset – Section_RawOffset + Section_VirtualAddress + ImageBase
            // VirtAddr + section_rawOffset - section va - image base = offset

            // Find the section this virtual addr is in

            var address = target - this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase;
            var section = this.PeFile.ImageSectionHeaders.First(x => AddressIsInSection((uint) address, x));

            return address + section.PointerToRawData - section.VirtualAddress;
        }

        public void StartDisassembly()
        {
            var epIp = this.CalculateIp();

            if (epIp != this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase)
            {
                this.AddressesToAnalyze.Enqueue(epIp);
            }

            if (this.PeFile.ExportedFunctions != null)
            {
                foreach (var export in this.PeFile.ExportedFunctions)
                {
                    var addr = this.PeFile.ImageNtHeaders.OptionalHeader.ImageBase + export.Address;

                    if (this.AddressesToAnalyze.Contains(addr))
                    {
                        continue;
                    }

                    Console.WriteLine($"Going to analyze exported func {export.Name} @ 0x{addr:X}");
                    this.AddressesToAnalyze.Enqueue(addr);
                }
            }

            this.Disassemble();

            foreach (var instr in this.Instructions.OrderBy(x => x.IP))
            {
                Console.WriteLine($"[0x{instr.IP:X}] {instr}");
            }
        }
    }
}