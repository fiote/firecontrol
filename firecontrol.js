module.exports = {};

module.exports.start = function(options) {
	if (!options) options = {};

	let settings = {
		port: 81, logs: false, test: false,
		secret: null, plain: false, zone: null,
		endpoint: '',
		folder: __dirname
	};

	settings = {...settings, ...options};

	// =====================================================
	// REQUIRES
	// =====================================================

	const express = require('express');
	const fs = require('fs');
	const exec = require('child_process').exec;


	// =====================================================
	// IP TABLE
	// =====================================================

	let IPtablePath = settings.folder+'/iptable.json';
	let IPtable = {};

	function saveIPs() {
		fs.writeFileSync(IPtablePath,JSON.stringify(IPtable,null,4));
	}

	function expireIPs() {
		var now = new Date().getTime();

		Object.keys(IPtable).forEach(zone => {
			var list = IPtable[zone];
			var expire = [];

			list = list.filter(entry => {
				var exp = entry.added + entry.duration;
				if (exp >= now) return true;				
				removeSource(zone,entry.ip).then(feed => {
					if (settings.logs) console.log(zone+'.'+entry.ip+' REMOVED');
				}).catch(err => {
					if (settings.logs) console.log(zone+'.'+entry.ip+' FAILED');
					if (settings.logs) console.log(err);
				});
			})

			IPtable[zone] = list; 
		});
		saveIPs();
	}

	function registerIP(zone,ip) {
		if (!IPtable[zone]) IPtable[zone] = [];
		var list = IPtable[zone];
		var entry = list.find(ex => ex.ip == ip);
		if (entry) {
			var index = list.indexOf(entry);
			list.splice(index,1);
		}

		var added = new Date().getTime();
		var duration = 1000*60*60*24;
		
		list.push({ip, added, duration});
		IPtable[zone] = list;
		saveIPs();

		return new Date(added+duration);
	}

	try {
		var content = fs.readFileSync(IPtablePath);
		IPtable = JSON.parse(content);
	} catch(e) {
		if (settings.logs) console.log(e);
		saveIPs();
	}

	expireIPs();
	setInterval(expireIPs,10*60*1000); // each 10 minutes

	// =====================================================
	// FIREWALL
	// =====================================================

	function removeSource(zone,source) {
		return actionSource('remove',zone,source);
	}

	function addSource(zone,source) {
		return actionSource('add',zone,source);
	}

	function actionSource(cmd,zone,source) {
		return new Promise((resolve,reject) => {
			zone = clearValue(zone);
			source = clearValue(source);	
			exec('firewall-cmd --permanent --zone='+zone+' --'+cmd+'-source='+source,{},(err, stdout, stderr) => {
				if (err) return reject(stderr);
				reloadFirewall().then(resolve).catch(reject);
			});
		});
	}

	function reloadFirewall() {
		return new Promise((resolve,reject) => {
			exec('firewall-cmd --reload',{},(err, stdout, stderr) => {
				if (err) return reject(stderr);
				resolve();
			});
		});
	}

	// =====================================================
	// Express/Route
	// =====================================================

	const app = express();
	var bodyParser = require('body-parser');
	app.use(bodyParser.json());
	app.use(bodyParser.urlencoded({ extended: true }));
	
	if (settings.test) {
		app.get('/',(req,res) => {	
			res.status(200);
			res.setHeader('Content-Type', 'text/html');
			res.send('Express seems to be working!');
		});
	}

	function outputJson(res,status,result) {
		res.header("Access-Control-Allow-Origin", "*");
		res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");

		if (settings.logs) {
			console.log('FN-SEND-JSON');
			console.log(status);
			console.log(result);
		}
		res.status(status);
		res.setHeader('Content-Type', 'application/json');
		res.send(JSON.stringify(result));
	}

	function checkSecret(req) {
		// if a secret is configured
		if (settings.secret) {
			let secret = (req.query && req.query.secret) || (req.body && req.body.secret);
			// assuming the key is wrong
			let trueKey = false;
			// if we should plain-check it (useful for custom hooks)
			if (settings.plain) {
				trueKey = (secret === settings.secret);
			} else {
				// if it's not a plain-check
			    let hmac = crypto.createHmac("sha1", settings.secret);
			    let digest = "sha1=" + hmac.update(JSON.stringify(req.body)).digest("hex");
				let checksum = req.headers["x-hub-signature"];
				trueKey = (checksum && digest && checksum === digest);
			}
			// if the key is not right
			if (!trueKey) return;
		}
		return true;
	}

	function clientIP(req) {
		return req.headers['x-forwarded-for'] || 
			req.connection.remoteAddress || 
			req.socket.remoteAddress ||
			(req.connection.socket ? req.connection.socket.remoteAddress : null);
	}

	function clearValue(value) {
		return value.replace(/[^a-zA-Z0-9.]+/g,"");
	}

	function getParams(req) {
		return {...req.query, ...req.body};
	}

	app.get(settings.endpoint+'/add', function (req, res) {	
		var auth = checkSecret(req);
		if (!auth) outputJson(res,401,{status:false, message:'Wrong secret key.'});
		var params = getParams(req);

		var zone = params.zone || settings.zone;
		if (!zone) outputJson(res,200,{'status':false, 'error':'zone not provided.'});

		var source = params.source;
		if (!source) outputJson(res,200,{'status':false, 'error':'source not provided.'});
		if (source == 'client') source = clientIP(req);
		
		addSource(zone,source).then(feed => {
			var expire = registerIP(zone,source);
			var status = true;
			var message = 'Source added (it will expire at '+expire.toLocaleString()+').';
			outputJson(res,200,{status,message});
		}).catch(err => {
			var status = false;
			var message = err;
			outputJson(res,200,{status,message});
		});
		
	});

	app.get(settings.endpoint+'/list', function (req, res) {	
		var auth = checkSecret(req);
		if (!auth) outputJson(res,401,{status:false, message:'Wrong secret key.'});
		var params = getParams(req);

		var zone = params.zone || settings.zone;
		if (!zone) outputJson(res,200,{'status':false, 'error':'Zone not provided.'});

		zone = clearValue(zone);

		exec('firewall-cmd --zone='+zone+' --list-all',{},(err, stdout, stderr) => {
			if (err) {
				var status = false;
				var error = stderr;
				outputJson(res,200,{status,error});
				return;
			}

			var lines = stdout.split("\n");
			var title = lines.shift();
			
			var config = {};
			var singles = ['target','icmp-block-inversion','masquerade'];

			lines.filter(line => line).forEach(line => {
				var pts = line.trim().split(':');
				var key = pts.shift();
				var value = pts.join(':');
				config[key] = (singles.indexOf(key) >= 0) ? value : value.split(' ');
			});

			outputJson(res,200,{status,title,config});
		});
	});

	// =====================================================
	// Listen
	// =====================================================

	app.listen(settings.port, function () {
		console.log('Express listening on port',settings.port,'!');
	});
};