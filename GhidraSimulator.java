//@author Tejvinder Singh Toor
//@category
//@keybinding
//@menupath
//@toolbar
//EXAMPLE: analyzeHeadless ~/github/thesis/samples thesis.gpr -process fib -postScript Pcode2LLVM.java -scriptlog ~/Desktop/GhidraProjects/script.log


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import ghidra.program.model.pcode.PcodeBlockBasic;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Attr;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.File;
import java.util.ArrayList;
import java.util.List;


public class GhidraSimulator extends HeadlessScript {

    @Override
    protected void run() throws Exception {

        DocumentBuilderFactory dFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        // program element
        Element rootElement = doc.createElement("program");
        doc.appendChild(rootElement);

        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");
        Language language = currentProgram.getLanguage();
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
        Listing listing = currentProgram.getListing();
        FunctionIterator fi = listing.getFunctions(true);
        Function func = null;

        Element globals = doc.createElement("globals");
        rootElement.appendChild(globals);
        Element memorys = doc.createElement("memory");
        rootElement.appendChild(memorys);
        List globalList = new ArrayList();
        List globalSizes = new ArrayList();
        List flags = new ArrayList();
        flags.add("ZF");
        flags.add("OF");
        flags.add("CF");
        flags.add("SF");
        List memoryList = new ArrayList();
        List memorySizes = new ArrayList();


        while (fi.hasNext()) {
            func = fi.next();

            // function element
            Element functionElement = doc.createElement("function");
            rootElement.appendChild(functionElement);
            Attr fnameAttr = doc.createAttribute("name");
            fnameAttr.setValue(func.getName());
            functionElement.setAttributeNode(fnameAttr);

            DecompileResults results = ifc.decompileFunction(func, 60, monitor);
            HighFunction hf = results.getHighFunction();
            Element basic_blocks = doc.createElement("basic_blocks");
            functionElement.appendChild(basic_blocks);
            ArrayList<PcodeBlockBasic> blockList = hf.getBasicBlocks();
            for(int i = 0; i < blockList.size(); i++){
                PcodeBlockBasic block = blockList.get(i);
                Element blockElement = doc.createElement("block_" + i);
                basic_blocks.appendChild(blockElement);
                Attr start = doc.createAttribute("start");
                start.setValue(block.getStart().toString());
                blockElement.setAttributeNode(start);
                Attr bEndAttr = doc.createAttribute("end");
                bEndAttr.setValue(block.getStop().toString());
                blockElement.setAttributeNode((bEndAttr));
            }

            Element foutputElement = doc.createElement("output");
            functionElement.appendChild(foutputElement);
            Attr foutputAttr = doc.createAttribute("type");
            if (!func.hasNoReturn()) {
                foutputAttr.setValue(func.getReturnType().getDisplayName());
            } else {
                foutputAttr.setValue("void");
            }
            foutputElement.setAttributeNode(foutputAttr);

            for (int x = 0; x < func.getParameterCount(); x++) {
                Element fInputElement = doc.createElement("input");
                functionElement.appendChild(fInputElement);
                Attr fInputTypeAttr = doc.createAttribute("type");
                fInputTypeAttr.setValue(func.getParameter(x).getDataType().getDisplayName());
                fInputElement.setAttributeNode(fInputTypeAttr);
                Attr fInputNameAttr = doc.createAttribute("name");
                fInputNameAttr.setValue(func.getParameter(x).getName());
                fInputElement.setAttributeNode(fInputNameAttr);
            }
            Address entry = func.getEntryPoint();
            InstructionIterator ii = listing.getInstructions(entry, true);
            int y = 0;
            Element instructions = doc.createElement("instructions");
            functionElement.appendChild(instructions);
            while (ii.hasNext()) {
                Instruction inst = ii.next();
                PcodeOp[] pcode = inst.getPcode();
                Element instructionElement = doc.createElement("instruction_" + y);
                instructionElement.appendChild(doc.createTextNode(inst.toString()));
                instructions.appendChild(instructionElement);
                if (y==0){
                    Attr funcAddress = doc.createAttribute("address");
                    funcAddress.setValue(String.valueOf(inst.getAddress())) ;
                    functionElement.setAttributeNode(funcAddress);
                }
                Element addressElement = doc.createElement("address");
                instructionElement.appendChild(addressElement);
                addressElement.appendChild(doc.createTextNode(String.valueOf(inst.getAddress())));
                Element pcodes = doc.createElement("pcodes");
                instructionElement.appendChild(pcodes);
                boolean endFunc = false;
                for (int i = 0; i < pcode.length; i++) {
                    Element pcodeElement = doc.createElement("pcode_" + i);
                    pcodes.appendChild(pcodeElement);
                    Varnode vnodeOutput = pcode[i].getOutput();
                    if (vnodeOutput != null) {
                        Element pOutputElement = doc.createElement("output");
                        pcodeElement.appendChild(pOutputElement);
                        pOutputElement.appendChild(doc.createTextNode(vnodeOutput.toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(vnodeOutput.getSize()));
                        pOutputElement.setAttributeNode(size);
                        Attr outIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (vnodeOutput.isRegister()) {
                            storage = "register";
                            String val = vnodeOutput.toString(language);
                            if (!globalList.contains(val)) {
                                globalList.add(val);
                                globalSizes.add("" + vnodeOutput.getSize());
                            }
                        } else if (vnodeOutput.isConstant()){
                            storage = "constant";
                        } else if (vnodeOutput.isAddress()) {
                            storage = "memory";
                            String val = vnodeOutput.toString(language);
                            if (!memoryList.contains(val)) {
                                memoryList.add(val);
                                memorySizes.add("" + vnodeOutput.getSize());
                            }
                        } else if (vnodeOutput.isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        outIsRegister.setValue(storage);
                        pOutputElement.setAttributeNode(outIsRegister);
                    }
                    Element iNameElement = doc.createElement("name");
                    pcodeElement.appendChild(iNameElement);
                    iNameElement.appendChild(doc.createTextNode(pcode[i].getMnemonic()));
                    if (pcode[i].getMnemonic().equals("RETURN")){
                        endFunc = true;
                    }
                    Attr inIsRegister;
                    Element inputs = doc.createElement("inputs");
                    pcodeElement.appendChild(inputs);
                    for (int j = 0; j < pcode[i].getNumInputs(); j++) {
                        Element pInputElement = doc.createElement("input_" + j);
                        inputs.appendChild(pInputElement);
                        pInputElement.appendChild(doc.createTextNode(pcode[i].getInput(j).toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(pcode[i].getInput(j).getSize()));
                        pInputElement.setAttributeNode(size);
                        inIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (pcode[i].getInput(j).isRegister()) {
                            storage = "register";
                            String val = pcode[i].getInput(j).toString(language);
                            if (!globalList.contains(val)) {
                                globalList.add(val);
                                globalSizes.add("" + pcode[i].getInput(j).getSize());
                            }
                        } else if (pcode[i].getInput(j).isConstant()){
                            storage = "constant";
                        } else if (pcode[i].getInput(j).isAddress()) {
                            storage = "memory";
                            String val = pcode[i].getInput(j).toString(language);
                            if (!memoryList.contains(val)) {
                                memoryList.add(val);
                                memorySizes.add("" + pcode[i].getInput(j).getSize());
                            }
                        } else if (pcode[i].getInput(j).isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        inIsRegister.setValue(storage);
                        pInputElement.setAttributeNode(inIsRegister);
                    }
                }
                if(endFunc){
                    break;
                }
                y++;
            }
        }
        int x = 0;
        while (x < globalList.size()){
            Element global = doc.createElement("register");
            globals.appendChild(global);
            Attr gName = doc.createAttribute("name");
            gName.setValue(String.valueOf(globalList.get(x).toString()));
            global.setAttributeNode(gName);
            Attr gSize = doc.createAttribute("size");
            gSize.setValue(String.valueOf(globalSizes.get(x)));
            global.setAttributeNode(gSize);
            x++;
        }
        x = 0;
        while (x < memoryList.size()){
            Element memory = doc.createElement("memory");
            memorys.appendChild(memory);
            Attr mName = doc.createAttribute("name");
            mName.setValue(String.valueOf(memoryList.get(x).toString()));
            memory.setAttributeNode(mName);
            Attr mSize = doc.createAttribute("size");
            mSize.setValue(String.valueOf(memorySizes.get(x)));
            memory.setAttributeNode(mSize);
            x++;
        }
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File("/tmp/output_simulator.xml"));
        transformer.transform(source, result);

        // Output to console for testing
        StreamResult consoleResult = new StreamResult(System.out);
        transformer.transform(source, consoleResult);
    }
}
