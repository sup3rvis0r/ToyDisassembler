namespace ToyDisassembler
{
    using System;
    using System.IO;

    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.Title = "Toy Disassembler";

            const string file = "learn_Re.exe";
            var peBytes = File.ReadAllBytes(file);

            Console.WriteLine($"Loaded PE File {file}");

            var disassembler = new PeDisassembler(peBytes);
            disassembler.StartDisassembly();
        }
    }
}