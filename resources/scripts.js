var window_focus = true;
window.onfocus = () => {
    window_focus = true;
    update();
}
window.onblur = () => {
    window_focus = false;
}

function byId(id) {
    return document.getElementById(id);
}

function boolean_changed(device) {
    let req = new XMLHttpRequest();
    req.onreadystatechange = requestReadyStateChange;
    req.open('PUT', '/device_state/' + device.id + '/' + device.checked, true);
    req.setRequestHeader('X-CSRFToken', document.csrf);
    req.send();
}

function update() {
    if (!window_focus) {
        return;
    }
    let req = new XMLHttpRequest();
    req.onreadystatechange = requestReadyStateChange;
    req.open('GET', '/device_state', true);
    req.send();
}

function requestReadyStateChange() {
    if (this.readyState == 4 && this.status == 200) {
        let data = JSON.parse(this.responseText);
        let boolean_devices = data.bool_ir_devices;
        for (let i = 0; i < boolean_devices.length; i++) {
            let device = boolean_devices[i];
            let element = byId(device.id);
            if (element) {
                element.checked = device.value;
            }
        }
    }
}

function init() {
    let boolean_devices = document.getElementsByClassName('boolean_device');
    for (let i = 0; i < boolean_devices.length; i++) {
        let device = boolean_devices[i];
        device.onchange = () => boolean_changed(device);
    }
    setInterval(update, 5000);
}



window.onload = init;
