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
    /* add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg 2222', false);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('hellooo new msg', true);
    add_new_msg('<script>alert(1);</script>', true); */
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
    var status1 = eel.add_new_user(ip_value)();
    if (status1 === true){
        add_user_btn();
        alert('Added Successfully');
    }
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
        alert('Error. Check \'errors.log\' file for more details');
    }
    // console.log(err);
}

setInterval(is_error, 5000);

var index1 = 0;
async function get_msg_list(){
    var user_list = await eel.get_user_list()();
    // console.log(user_list);
    for (let index = 0; index < user_list.length; index++) {
        const element = user_list[index];
        const msg_0 = document.createElement('div');
        msg_0.setAttribute('id', 'message');
        const msg = document.createElement('h3');
        msg.setAttribute('id', 'sender');
        msg_0.dataset.index = index1;
        index1++;
        msg.innerHTML = element[0];
        msg_0.appendChild(msg);
        document.getElementById('message_list').appendChild(msg_0);
    }
}

function create_msg_element(message_text, send){
    const messageElement = document.createElement('div');
    messageElement.textContent = message_text;
    messageElement.setAttribute('id', 'message_text1')
    if (send === true){
        messageElement.setAttribute('class', 'sent_msg');
    } else if (send === false) {
        messageElement.setAttribute('class', 'recvd_msg');
    }
    return messageElement;
}

eel.expose(add_new_msg);
function add_new_msg(message_text, send){
    const message1div = document.getElementById('message_spacer');
    const new_message_element = create_msg_element(message_text, send);
    // console.log(message1div.children);

    // const second_to_last_child = message1div.children[message1div.children.length - 2];
    // message1div.insertBefore(new_message_element, second_to_last_child);
    message1div.appendChild(new_message_element);
}

get_msg_list();


function send_msg(){
    input = document.getElementById('message_input');
    // complete aakanam
}


// const divs = document.querySelectorAll('#message');
// divs.forEach(div => {
//     div.addEventListener('click', function(event){
//         const clicked_div = event.currentTarget;
//         const div_index = Array.from(divs).indexOf(clicked_div);
//         console.log('Clicked div index:', div_index);
//     })
// })


async function get_msg_for_usr(div1){
    var user = div1.textContent;
    const message1div = document.getElementById('message_spacer');
    message1div.replaceChildren();
    var get = await eel.get_user_msg_list(user)();
    // console.log(message_list);
}

document.addEventListener('DOMContentLoaded', function() {
    const parentElement = document.getElementById('message_list'); // Assuming a parent element
  
    parentElement.addEventListener('click', function(event) {
      if (event.target.closest('#message')) { // Check if the clicked element is a div with id "message"
        const clickedDiv = event.target.closest('#message');
        const divIndex = clickedDiv.dataset.index;
        // console.log('Clicked div index:', divIndex);
        // alert('Clicked:'+ divIndex);
        get_msg_for_usr(clickedDiv);
        const msg_div = document.getElementById('message1');
        msg_div.style.display = 'flex';
      }
    });
});
