/**
 * Demo Suspicious Extension
 * 
 * This extension contains INTENTIONALLY SUSPICIOUS patterns for demonstration purposes.
 * It is designed to test security scanners and malware detection tools.
 * 
 * WARNING: DO NOT USE THIS IN PRODUCTION!
 */

const vscode = require('vscode');
const { exec } = require('child_process');

/**
 * Extension activation
 */
function activate(context) {
    console.log('Demo extension is now active');

    // TEST 1: Dynamic Code Execution with Base64 (CRITICAL - Will be flagged)
    // This pattern is commonly used in malware
    const encodedGreeting = 'Y29uc29sZS5sb2coIkhlbGxvIGZyb20gZGVtbyBleHRlbnNpb24hIik=';
    eval(atob(encodedGreeting));

    // TEST 2: Command Execution (HIGH - Will be flagged)
    // Executing system commands is potentially dangerous
    exec('echo "Demo extension loaded"', (error, stdout, stderr) => {
        if (!error) {
            console.log(stdout);
        }
    });

    // TEST 3: Invisible Characters (MEDIUM - Will be flagged)
    // Zero-width space hidden in the code
    const userName​ = vscode.workspace.getConfiguration().get('user.name');

    // TEST 4: Excessive Indentation (MEDIUM - Will be flagged)
    // Code hidden far off-screen with extreme indentation
    function hiddenCode() {
                                                                                                                                                                                                                                                                                                    console.log('This code is hidden with excessive indentation');
    }

    // TEST 5: Unicode Steganography - Hidden payload (CRITICAL - Will be flagged)
    // Using Unicode Variation Selectors to hide data
    const hiddenData = '󠀀󠀁󠀂󠀃󠀄󠀅󠀆󠀇󠀈󠀉󠀊󠀋󠀌󠀍󠀎󠀏󠀐󠀑󠀒󠀓󠀔󠀕󠀖󠀗󠀘󠀙󠀚󠀛󠀜󠀝󠀞󠀟';

    // TEST 6: More Dynamic Code Execution (CRITICAL - Will be flagged)
    const dynamicFunc = new Function(atob('cmV0dXJuICJEeW5hbWljIGZ1bmN0aW9uIGV4ZWN1dGlvbiI='));
    
    // TEST 7: Promise chain with eval (CRITICAL - Will be flagged)
    Promise.resolve('Y29uc29sZS5sb2coIlByb21pc2UgY2hhaW4gd2l0aCBldmFsIik=')
        .then(atob)
        .then(eval);

    // Register a command
    let disposable = vscode.commands.registerCommand('demoExtension.hello', function () {
        vscode.window.showInformationMessage('Hello from Demo Suspicious Extension!');
    });

    context.subscriptions.push(disposable);

    // TEST 8: Buffer with toString (MEDIUM - Will be flagged)
    const encoded = Buffer.from('VGVzdCBkYXRh', 'base64').toString();
    
    // TEST 9: Homoglyph attack - Cyrillic 'a' instead of Latin 'a' (MEDIUM - Will be flagged)
    const usеrName = 'test'; // The 'е' is Cyrillic

    // Normal, legitimate code for comparison
    vscode.window.showInformationMessage('Demo extension activated. Check security scanner for findings!');
}

/**
 * Extension deactivation
 */
function deactivate() {
    console.log('Demo extension deactivated');
}

module.exports = {
    activate,
    deactivate
};

