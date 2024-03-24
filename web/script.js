/*async function test_fn(){
    console.log('eel');
    ffb = await eel.ui()();
    console.log('Writing html');
    document.querySelector('.hlo').innerHTML = ffb;
    console.log('completed');
}
*/

function init(){
    is_new_user();
}

function gofullscreen(){
    if (document.documentElement.requestFullscreen) {
        document.documentElement.requestFullscreen();
        console.log('fullscreen');
    } else if (document.documentElement.mozRequestFullscreen) {
        document.documentElement.mozRequestFullscreen;
    } else if (document.documentElement.webkitRequestFullscreen) {
        document.documentElement.webkitRequestFullscreen;
    }
}

function toggle_settings() {
    const settings = document.getElementById('settings_panel');
    const body_cls = document.getElementById('bodyy')
    if (settings.style.display === 'none'){
        settings.classList.toggle('hidden');
        settings.classList.toggle('show_popup');
        // settings.style.opacity = 1;
        body_cls.classList.toggle('body_blr');
    } else {
        // settings.style.display = 'none';
        settings.classList.toggle('hidden');
        settings.classList.toggle('show_popup');
        body_cls.classList.toggle('body_blr');
    }
}

function add_user_btn(){
    const add_usr_panel = document.getElementById('add_usr_popup')
    const body_cls = document.getElementById('bodyy')
    add_usr_panel.classList.toggle('hidden1')
    body_cls.classList.toggle('body_blr1')
}

function add_user(){
    const ip_in = document.getElementById("ip_addr");
    var ip_value = ip_in.value;
    console.log(ip_value);
    eel.add_new_user(ip_value)();
}

async function is_new_user(){
    const new_user_popup = document.getElementById('new_user')
    const body_cls = document.getElementById('bodyy')
    var new_user = await eel.is_new_user()();
    console.log(new_user);
    if (new_user === true);{
        new_user_popup.classList.remove('hidden2');
        body_cls.classList.add('body_blr2');
    }
    if (new_user === false){
        new_user_popup.classList.add('hidden2');
        body_cls.classList.remove('body_blr2');
    }
}

async function add_new_user(){
    const user_name_element = document.getElementById('new_user_id');
    var user_id = user_name_element.value;
    if (user_id === ''){
        alert('Please Enter a User ID');
        is_new_user();
    } else {
        var is_successful = await eel.new_user(user_id)();
        if (is_successful) {
            alert('User Added')
            is_new_user();
        } else {
            alert('Failed')
            is_new_user();
        }
    }
}

async function open_license(){
    eel.open_license()();
}

async function is_error(){
    var err = await eel.is_error()();
    if (err === true){
        alert('Error');
    }
    // console.log(err);
}

setInterval(is_error, 5000)

async function get_msg_list(){}