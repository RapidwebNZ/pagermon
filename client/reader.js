//
// PagerMon - reader.js
// 2017-06-04
// Author: Dave McKenzie
//
// Description: Takes output of multimon-ng and pushes to PagerMon server
//
// Usage: Invoke via a shell script, ideally
// 		If not, just pipe multimon's output to it
//
// Example: reader.sh
//

// CONFIG
// create config file if it does not exist, and set defaults
var fs = require('fs');
var conf_defaults = require('./config/default.json');
var confFile = './config/config.json';
if (!fs.existsSync(confFile)) {
    fs.writeFileSync(confFile, JSON.stringify(conf_defaults, null, 2));
    console.log('created config file - set your api key in ' + confFile);
    return;
}
// load the config file
var nconf = require('nconf');
nconf.file({ file: confFile });
nconf.load();

var hostname = nconf.get('hostname');
var apikey = nconf.get('apikey');
var identifier = nconf.get('identifier');
var sendFunctionCode = nconf.get('sendFunctionCode') || false;
var useTimestamp = nconf.get('useTimestamp') || true;
var EASOpts = nconf.get('EAS'); // Import EAS Config Object Ref Pull 435


// Check if hostname is in a valid format - currently only removes trailing slash - possibly expand to validate the whole URI?
var uri;
if (hostname.substr(-1) === '/') {
    uri = hostname.substr(0, hostname.length - 1) + '/api/messages';
} else {
    uri = hostname + '/api/messages';
}

var http = require('http');
var request = require('request');
require('request').debug = true;
var rp = require('request-promise-native');
var moment = require('moment');

var colors = require('colors/safe');
colors.setTheme({
    success: ['white', 'bold', 'bgBlue'],
    error: ['red', 'bold', 'bgwhite']
});

const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    terminal: true
});

var frag = {};
var SAME = require('jsame'); // Import jSAME EAS decode 
rl.on('line', (line) => {
    // console.log(`Received: ${line.trim()}`);
    var time = moment().format("YYYY-MM-DD HH:mm:ss");
    var timeString = '';
    var datetime = moment().unix();
    var address;
    var message;
    var trimMessage;

    if (/POCSAG(\d+): Address: /.test(line)) {
        let addressMatch = line.match(/POCSAG(\d+): Address:(.*?)Function/);
        if (addressMatch && addressMatch[2]) {
            address = addressMatch[2].trim();
            if (sendFunctionCode) {
                let functionMatch = line.match(/POCSAG(\d+): Address:(.*?)Function: (\d)/);
                if (functionMatch && functionMatch[3]) {
                    address += functionMatch[3];
                }
            }
            if (line.indexOf('Alpha:') > -1) {
                let messageMatch = line.match(/Alpha:(.*?)$/);
                if (messageMatch && messageMatch[1]) {
                    message = messageMatch[1].trim();
                    if (useTimestamp) {
                        let timeMatch = message.match(/\d{2} \w+ \d{4} \d{2}:\d{2}:\d{2}/) || message.match(/\d+-\d+-\d+ \d{2}:\d{2}:\d{2}/);
                        if (timeMatch) {
                            timeString = timeMatch[0];
                            if (moment(timeString, ['DD MMMM YYYY HH:mm:ss', 'YYYY-MM-DD HH:mm:ss']).isValid()) {
                                datetime = moment(timeString, ['DD MMMM YYYY HH:mm:ss', 'YYYY-MM-DD HH:mm:ss']).unix();
                                message = message.replace(timeString, '');
                            }
                        }
                    }
                    trimMessage = message.replace(/<[A-Za-z]{3}>/g, '').replace(/Ä/g, '[').replace(/Ü/g, ']').trim();
                }
            } else if (line.indexOf('Numeric:') > -1) {
                let numericMatch = line.match(/Numeric:(.*?)$/);
                if (numericMatch && numericMatch[1]) {
                    message = numericMatch[1].trim();
                    trimMessage = message.replace(/<[A-Za-z]{3}>/g, '').replace(/Ä/g, '[').replace(/Ü/g, ']');
                }
            } else {
                message = false;
                trimMessage = '';
            }
        }
    } else if (line.match(/FLEX[:|]/)) {
        let addressMatch = line.match(/FLEX[:|] ?.*?[\[|](\d*?)[\]| ]/);
        if (addressMatch && addressMatch[1]) {
            address = addressMatch[1].trim();
            if (useTimestamp) {
                let timeMatch = line.match(/FLEX[:|] ?\d{2} \w+ \d{4} \d{2}:\d{2}:\d{2}/) || line.match(/FLEX[:|] ?\d+-\d+-\d+ \d{2}:\d{2}:\d{2}/);
                if (timeMatch) {
                    timeString = timeMatch[0];
                    if (moment(timeString, ['DD MMMM YYYY HH:mm:ss', 'YYYY-MM-DD HH:mm:ss']).isValid()) {
                        datetime = moment(timeString, ['DD MMMM YYYY HH:mm:ss', 'YYYY-MM-DD HH:mm:ss']).unix();
                    }
                }
            }
            let messageMatch = line.match(/([ |]ALN[ |]|[ |]GPN[ |]|[ |]NUM[ |])/);
            if (messageMatch) {
                let flexMessageMatch = line.match(/FLEX[:|].*[|\[][0-9 ]*[|\]] ?...[ |](.+)/);
                if (flexMessageMatch && flexMessageMatch[1]) {
                    message = flexMessageMatch[1].trim();
                    if (line.match(/[ |][0-9]{4}\/[0-9]\/F\/.[ |]/)) {
                        // message is fragmented, hold onto it for next line
                        frag[address] = message;
                        message = false;
                        trimMessage = '';
                    } else if (line.match(/[ |][0-9]{4}\/[0-9]\/C\/.[ |]/)) {
                        // message is a completion of the last fragmented message
                        trimMessage = frag[address] + message;
                        delete frag[address];
                    } else if (line.match(/[ |][0-9]{4}\/[0-9]\/K\/.[ |]/)) {
                        // message is a full message
                        trimMessage = message;
                    } else {
                        // message doesn't have the KFC flags, treat as full message
                        trimMessage = message;
                    }
                }
            }
        }
    } else if (line.match(/(EAS[:|]|ZCZC-)/)) {
        var decodedMessage = SAME.decode(line, EASOpts.excludeEvents, EASOpts.includeFIPS);
        if (decodedMessage) {
            if (EASOpts.addressAddType) {
                address = decodedMessage["LLLL-ORG"] + '-' + decodedMessage["type"];
            } else {
                address = decodedMessage["LLLL-ORG"];
            }
            message = decodedMessage;
            trimMessage = decodedMessage["MESSAGE"];
            datetime = moment().unix();
        } else {
            address = '';
            message = false;
            trimMessage = '';
        }
    } else {
        address = '';
        message = false;
        trimMessage = '';
    }

    // filter out most false hits
    // if too much junk data, make sure '-p' option isn't enabled in multimon
    if (address.length > 2 && message) {
        var padAddress = padDigits(address, 7);
        console.log(colors.red(time + ': ') + colors.yellow(padAddress + ': ') + colors.success(trimMessage));
        // now send the message
        var form = {
            address: padAddress,
            message: trimMessage,
            datetime: datetime,
            source: identifier
        };
        sendPage(form, 0);
    } else {
        console.log(colors.red(time + ': ') + colors.grey(line));
    }
}).on('close', () => {
    console.log('Input died!');
});

var sendPage = function (message, retries) {
    var options = {
        method: 'POST',
        uri: uri,
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'PagerMon reader.js',
            apikey: apikey
        },
        form: message
    };
    rp(options)
        .then(function (body) {
            // console.log(colors.success('Message delivered. ID: '+body)); 
        })
        .catch(function (err) {
            console.log(colors.yellow('Message failed to deliver. ' + err));
            if (retries < 10) {
                var retryTime = Math.pow(2, retries) * 1000;
                retries++;
                console.log(colors.yellow(`Retrying in ${retryTime} ms`));
                setTimeout(sendPage, retryTime, message, retries);
            } else {
                console.log(colors.yellow('Message failed to deliver after 10 retries, giving up'));
            }
        });
};

var padDigits = function (number, digits) {
    return Array(Math.max(digits - String(number).length + 1, 0)).join(0) + number;
};
