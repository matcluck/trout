# trout
# Description
Well... it's currently 4.30AM and I'm lying in bed thinking you know what would be great? A tool that can both detect AND exploit vulnerable Group Policy Objects (GPOs)! Well that's what `trout` is.

`trout` is a C# tool that allows pentesters/red teamers to target Group Policy. The tool contains two modes, a `detect` mode, that searches AD for instances of exploitable GPOs, an `exploit` mode, that performs the exploitation, and a `cleanup` mode, because... yeah we're messing with Group Policy.

# Detect Mode
`trout detect`

Detect mode looks for GPOs with the following primitives:
1. The ability to modify the GPO's AD Object.
2. The ability to modify the GPO's backing store in `SYSVOL`.
3. That the GPO is currently enabled, and linked to an Organizational Unit (OU).
4. That security filtering is targeting the GPO to at least 1 user or computer within linked OUs.

# Exploit Mode
`trout exploit`

Exploit mode allows exploition of vulnerable GPOs. Specifically, it works by modifying the GPO to add a supplied user or group to the target/s local `Administrators` group. Since we're dealing with Group Policy, this mode will provide verbose output that states every change it is making to AD and SYSVOL so it can be reverted once complete. This mode will return a JSON string of modifications, that can be used with cleanup mode.

# Cleanup Mode
`trout cleanup`

Does what it says on the tin. Provide this mode with the JSON output from exploit mode and it will revert any changes made for exploitation.

# License
```
MIT License

Copyright (c) 2025 matcluck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
