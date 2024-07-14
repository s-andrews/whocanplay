$( document ).ready(function() {

    if (location.protocol !== 'https:') {
        location.replace(`https:${location.href.substring(location.protocol.length)}`);
    }

    // Action when they log out
    $("#logout").click(logout)

})



function logout() {
    Cookies.remove("capstone_session_id")
    location.replace("/");

}


function process_login() {

    // Clear the password so they can't do it again
    $("#password").val("")

    // Add a spinner so they know it's trying!
    $("#login").html(`<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Checking`)
    $("#login").prop("disabled",true)
    $("#username").prop("disabled",true)
    $("#password").prop("disabled",true)


}

