    const selected = [];
	objList = [];
	const samenessFields = ["acl_policy", "arp_inspection", "arp_ip_local_proxy", "arp_proxy", "arp_timeout", "bfd", "client_track_ip", "client_track_ip_interval", "description", "dhcpv4_snooping", "flow_control", "igmp_policy", "ip", "ip_directed_broadcast", "ip_mtu", "ip_urpf_check", "ipv4_source_lockdown", "l3_counters", "lag", "lldp_policy", "loop_protect", "loop_protect_action", "mac_notify", "mtu", "nd_snooping", "poe", "poe_allocatedby", "poe_class", "poe_pdoverride", "poe_pre_std", "poe_priority", "port_security", "port_seceurity_profile", "qos_policy", "routing", "sflow", "shutdown", "spantree_profile", "speed", "sub_interface", "switch_name", "switch_port_policy", "track", "trunk", "udld", "vlan_access", "vrf", "vrrp"];
	const portDiffProfiles = [];
	const portsSelectedData = [];

    function changeFocus(elem, cl) {
        clearFocus('blink-dash-clear');
        clearFocus('blink-blue-white');
        elem.classList.add(cl);
    }

	function theSame(arr) {
		let same=true;
		for (i=0;i<arr.length;i++){
			if (arr[i] != arr[0]) { same=false; }
		}
		return (same);
	}

	function onlyIncludes(arr, v) {
		let only=true;
		for (i=0;i<arr.length;i++){
			if (!(v.includes(arr[i]))) { only=false; }
		}
		return (only);
	}

	function switchCount(arr) {
		let seen=[];
		for (i=0;i<arr.length;i++) {
			if (!seen.includes(arr[i].switch_number)){
				seen.push(arr[i].switch_number);
			}
		}
		return(seen.length);
	}

	function getSwitch(sw) {
		let r=[];
		for (let i=0; i<=window.switchApp.sw.length; i++) {
			if (window.switchApp.sw[i].switch_number == sw) {
				r = window.switchApp.sw[i];
				break;
			}
		}
		return (r);
	}

	function loadPortData(e) {
		let thisPortObject=document.getElementById(e.id);
		let thisSwitch=thisPortObject.getAttribute("switch_number");
		let thisPort=thisPortObject.getAttribute("port");
		//let thisSwitchData=window.switchApp.sw[thisSwitch-1];
		//old way with stacks each was next index - not case with cards in chassis so new func that gets the switch info based on sw number
		let thisSwitchData=getSwitch(thisSwitch);
		let thisPortData=JSON.parse(JSON.stringify(thisSwitchData.ports[thisPort]));
		return ({switch:thisSwitch,port:thisPort,data:thisPortData});
	}

	function portDataSame() {
		let same=true;
		portDiffProfiles.splice(0, portDiffProfiles.length);
		for (let i=0; i<portsSelectedData.length; i++) {
			let p=portsSelectedData[i]["data"]["port"]
			let s=portsSelectedData[i]["data"]["switch_number"]+1
			portDiffProfiles.push({switch_number: s, port: p, value: s+"_"+p, name:s+"/1/"+p});
			samenessFields.forEach((field) => {
				if (portsSelectedData[i]["data"][field] != portsSelectedData[0]["data"][field]) {
					same=false;
				}
			});
		}
		window.switchApp.switch_PortData.sourcePort = portDiffProfiles[0].value;
		return (same);
	}

	function buttonHandler(e, cl) {
		//console.error(e.getAttribute('button_text'));		
		//console.error("slot ", e.getAttribute('slot'));
		//console.error("switch_number ", e.getAttribute('switch_number'));
		//console.error("switch_name ", e.getAttribute('switch_name'));
		switch (e.getAttribute('button_text')) {
			case 'REMOVE':
				//This calls the function in vue_switch.html: "are_you_sure" which passes to the function "remove_switch_card"
				window.switchApp.are_you_sure(window.switchApp.remove_switch_card, (e.getAttribute('slot')));
				break;
			case 'CHANGE':
				break;
			case 'ADD CARD':
				//This calls the function in vue_switch.html: "switch_toggleAddCardData"
				window.switchApp.switch_toggleAddCardData(e.getAttribute('slot'));
				break;
		}
	}

function selectHandler(elem, cl) {
	//console.log("selectHandler start *************");
	let typesSelected = [];
	portsSelectedData.splice(0, portsSelectedData.length);
	//console.log("selected arry: ", selected);
	selected.forEach((e) => { 
		document.getElementById(e.id).classList.remove(e.cls);
	});
	index = selected.findIndex((e) => e.id === elem);
	if (index >= 0) {
		selected.splice(index, 1);
	} else {
		//log the selected item
		//console.log("elem: ", elem);
		//console.log("cl: ", cl);
		selected.push({ id: elem, cls: cl });
	}
	if (selected.length==1) {
		window.switchApp.switch_PortData.same=true;
		window.switchApp.switch_PortData.multiEdit = false;
		selected.forEach((e) => { portsSelectedData.push(loadPortData(e)); });
		window.switchApp.switch_PortData.sourcePort = portsSelectedData[0].switch+"_"+portsSelectedData[0].port;
	}
	if (selected.length>1) {
		window.switchApp.switch_PortData.multiEdit = true;
		selected.forEach((e) => { portsSelectedData.push(loadPortData(e)); });
		window.switchApp.switch_PortData.same=portDataSame();
		window.switchApp.switch_PortData.distinctPorts = JSON.parse(JSON.stringify(portDiffProfiles));
	}
	if (selected.length > 0) {
			objList = [];
			selected.forEach((e) => { 
				let record = document.getElementById(e.id);
				objList.push({
					switch_name:record.getAttribute("switch_name"), 
					switch_number:record.getAttribute("switch_number"), 
					port:record.getAttribute("port"),
					port_type:record.getAttribute("port_type")
				});
				typesSelected.push(parseInt(record.getAttribute("port_type")));
			});
			if (theSame(typesSelected) && typesSelected[0]==0) {
				window.switchApp.vue_register_button("Insert SFP", "gmiLtBlue", window.switchApp.switch_toggleSFPAddData);
				window.switchApp.vue_deregister_buttons(["Change SFP"]);
			} else {
				window.switchApp.vue_deregister_buttons(["Insert SFP"]);
				if (onlyIncludes(typesSelected, [0,1,2])) {
					window.switchApp.vue_register_button("Change SFP", "gmiLtBlue", window.switchApp.switch_toggleSFPAddData);
				}
				else {
					window.switchApp.vue_deregister_buttons(["Change SFP"]);
				}
			}
			window.switchApp.vue_register_button("Clear Selection", "gmiLtBlue", clearSelected);
			window.switchApp.vue_register_button("Change Port", "gmiLtBlue", window.switchApp.switch_toggleAddPortProperties);
			window.switchApp.vue_register_button("Toggle Shutdown", "gmiRed", window.switchApp.switch_disable_ports);
			window.switchApp.vue_register_button("Zeroize Port", "gmiDkRed", window.switchApp.are_you_sure, "in", window.switchApp.switch_zeroize_ports);
			if (onlyIncludes(typesSelected, [9])) {
				window.switchApp.vue_register_button("Toggle POE", "gmiRed", window.switchApp.switch_disable_power);
			} else {
				window.switchApp.vue_deregister_buttons(["Toggle POE"]);
			}
			/*
			This was removed becuase the "Make Trunk" and "Make LAG" buttons called functions that never worked.
			if (selected.length==1) {
					window.switchApp.vue_deregister_buttons(["Make LAG"]);
					window.switchApp.vue_register_button("Make Trunk", "gmiLtBlue", window.switchApp.switch_toggleMakeTrunkPort);
			} else {
				window.switchApp.vue_deregister_buttons(["Make Trunk"]);
			}
			*/
			if (selected.length>1 && onlyIncludes(typesSelected, [1,2,9])) {
				//window.switchApp.vue_register_button("Make LAG", "gmiLtBlue", window.switchApp.switch_toggleMakeLagPort);
				if (switchCount(objList)>1 && onlyIncludes(typesSelected, [1,2])) {
					window.switchApp.vue_register_button("Stack Ports", "gmiLtBlue", window.switchApp.switch_toggleStackPorts);
				} else {
					window.switchApp.vue_deregister_buttons(["Stack Ports"]);
				}
			} else {
				window.switchApp.vue_deregister_buttons(["Stack Ports"]);
			}
		} else {
				window.switchApp.vue_deregister_buttons(["Clear Selection","Change Port","Toggle Shutdown","Toggle POE","Make LAG", "Insert SFP", "Change SFP", "Stack Ports", "Make Trunk", "Zeroize Port"]);
		}
		
        selected.forEach((e) => document.getElementById(e.id).classList.add(e.cls));
		document.getAnimations().forEach(anim => anim.currentTime = 0);
		//console.log("selecHandler end *************");
    }

	function clearSelected() {
		selected.forEach((e) => document.getElementById(e.id).classList.remove(e.cls));
		selected.splice(0,selected.length);
		window.switchApp.vue_deregister_buttons(["Clear Selection","Change Port","Make LAG","Toggle Shutdown","Toggle POE","Change SFP","Insert SFP","Make Trunk","Zeroize Port"]);
	}

    function clearFocus(cl) {
        elemList = document.getElementsByClassName(cl);
        Object.entries(elemList).forEach(element => element[1].classList.remove(cl));
    }

