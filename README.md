# Introduction

rtfraptor is a simple tool to aid analysis of malicious RTF files.

It works by running Word and intercepting calls to OLEv1 functions.  This allows raw OLE objects to be dumped
from memory for further analysis.  The tool is designed to be run on Windows.

This is useful for:

* Avoiding manual analysis of obfuscated RTF files.
* Extracting malicious objects (packager objects, Equation Editor abuse, embedded documents etc.).
* Identifying what vulnerabilities (or features) a RTF document is trying to abuse.
* Verifying the output of other tools (e.g. static document parsers).

The tool was written by [David Cannings](https://twitter.com/edeca) and is released under the AGPL.

# Example

## Installation

Install rtfraptor like so:

    $ pip install rtfraptor

This will automatically fetch and install dependencies.  It is recommended to install in a 
[virtual environment](https://virtualenv.pypa.io/en/latest/userguide/).

## Usage

TODO

**Note:** this tool runs Word.  Analysis of suspicious documents should be done inside a virtual machine.  The tool 
**does not** stop any final payload from executing, and you may wish to isolate the virtual machine from any 
networking. 

## Output

## JSON output

TODO - insert an image of the output

# FAQ

## What do I need to make it work?

At minimum you'll need:
 
 * Windows - tested on 7, should work from XP to 10
 * Python 2 - tested on 2.7.15 (32-bit)
 * Word - tested with Office 2013 (32-bit)
 
In theory 64-bit versions of Office and Python should work.  The Python interpreter needs to match Office.

## Why use this instead of `rtfobj`?

Static analysis is clearly preferable in many cases.  However, it's never perfect and emulating a complex parser 
brings a lot of challenges.

Using this tool you are guaranteed to obtain accurate OLEv1 data from Word, after RTF obfuscation has been 
dealt with.  At minimum it proves useful for comparing the output of other tools.

## Does it work with any Microsoft Office program?

In theory yes.  Word, Excel and Powerpoint should all use the same parts of `ole32.dll`.  

However, the current approach is aimed at OLEv1.  This is used by RTF but is considered legacy.  Other formats such as 
Composite Document Format (CDF, as used by `.doc` / `.xls`) and OOXML (as used by `.docx` / `.xslx`) do not typically 
use OLEv1.

## What versions of Office are supported?

This tool was tested with Office 2013.  It should work with any 32-bit desktop version of Office.

It's likely that changes would be required to support 64-bit versions of Office.  If there is significant demand this 
can be investigated further.

## How does it work?

At present the code hooks three functions which are involved in loading an OLEv1 object:

 * `ole32!OleConvertOLESTREAMToIStorage` - which converts legacy OLEv1 objects to an objects implementing `IStorage`.
 * `ole32!OleLoad` - which is called when an OLEv1 object is loaded.
 * `ole32!OleGetAutoConvert` - which is called by `OleLoad` to convert the GUID. 

This chain of functions provides the raw OLEv1 data, confirmation it has been loaded and finally the class identifier.

The method is slightly fragile as `ole32!OleGetAutoConvert` can be called from other (benign) sources.  A better 
approach would be to understand the layout of `IStorage` in memory, which might allow a single hook on `ole32!OleLoad`.

## Can this approach be extended?

Yes.  The primary reason this proof-of-concept has been released is because it can be used in other ways.

For example, it's possible to intercept calls to functions such as `packager!CopyStreamToFile` or parts of Equation 
Editor.  Using this approach you can check function arguments at strategic points to look for invalid data, which 
helps confirm the vulnerability (or feature) being exploited.

You can also catch *all* calls to OLE functions (e.g. `combase!StringFromCLSID`) and compare what a "normal" 
document does versus a malicious one.  Using this method it's possible to spot abuse of legitimate features, use of 
Windows scripting languages, potential exploitation of new vulnerabilities etc.  

But be careful - Office applications make use of COM for lots of legitimate purposes (including activation) so you'll 
need to filter out known good :)

## Can I embed this in my own processing?

Yes.  The tool is a Python module that can be used from within your own code.  

See `rtfraptor.engine` for the core code and `rtfraptor.app` for the example implementation.

## Why only Python 2?

Although I love Python 3, the debugging library used (winappdbg) currently only supports Python 2.

# Known issues

The target application (typically Word) is forcibly killed after the timeout expires.  This can cause a Safe Mode 
prompt next time the application is started, for example if there is a popup waiting for user input. 

# See also

The following resources are useful:

* The [blog post](http://malwageddon.blogspot.com/2018/11/deobfuscation-tips-rtf-files.html) by 
  [Denis O'Brien](https://twitter.com/Malwageddon) that inspired this tool.
* [rtfobj](https://github.com/decalage2/oletools/wiki/rtfobj), part of oletools by 
  [Decalage](https://twitter.com/decalage2).
* This [Blackhat 2015 presentation](https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf) 
  on "Attacking Interoperability" by [Haifei Li](https://twitter.com/HaifeiLi).
* The Twitter account for [Mario Vilas](https://twitter.com/Mario_Vilas) who wrote 
  [winappdbg](https://github.com/MarioVilas/winappdbg).