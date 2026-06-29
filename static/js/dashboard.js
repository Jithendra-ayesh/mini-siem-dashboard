let loginChart;
let eventChart;
let usernameChart;
let ipChart;
let dailyChart;
let hourlyChart;
let threatChart;
let selectedDay = null;
let analyticsFilter = 7;

function initializeCharts() {

    loginChart = new Chart(
        document.getElementById("loginChart"),
        {
            type: "pie",
            data: {
                labels: [
                    "Successful Logins",
                    "Failed Logins"
                ],
                datasets: [{
                    data: [
                        dashboardData.successfulLogins,
                        dashboardData.failedLogins
                    ]
                }]
            },
            options:{
                responsive:true,
                maintainAspectRatio:false
            }
        }
    );

    eventChart = new Chart(
        document.getElementById("eventChart"),
        {
            type: "bar",

            data: {
                labels: [
                    "Total Events",
                    "Successful",
                    "Failed"
                ],

                datasets: [{
                    label: "Security Events",

                    data: [
                        dashboardData.totalEvents,
                        dashboardData.successfulLogins,
                        dashboardData.failedLogins
                    ]
                }]
            }
        }
    );

    usernameChart = new Chart(
        document.getElementById("usernameChart"),
        {
            type: "bar",

            data: {
                labels: dashboardData.usernameLabels,

                datasets: [{
                    label: "Targeted Usernames",
                    data: dashboardData.usernameCounts
                }]
            },
            options:{
                indexAxis:"y"
            }
        }
    );

    ipChart = new Chart(
        document.getElementById("ipChart"),
        {
            type: "bar",

            data: {
                labels: dashboardData.ipLabels,

                datasets: [{
                    label: "Source IP Activity",
                    data: dashboardData.ipCounts
                }]
            },
            options:{
                indexAxis:"y"
            }
        }
    );

    dailyChart = new Chart(
        document.getElementById("dailyChart"),
        {
            type: "line",

            data: {
                labels: dashboardData.dailyLabels,

                datasets: [{
                    label: "Events Per Day",
                    data: dashboardData.dailyCounts
                }]
            },
            elements:{
                point:{
                    radius:4
                }
            }
        }
    );

    dailyChart.options.onClick = function(event, elements){

        if(elements.length === 0){
            return;
        }

        const index = elements[0].index;
        selectedDay = 
           dailyChart.data.labels[index];

        fetch("/hourly/" + selectedDay)

        .then(response => response.json())
        .then(data => {

            hourlyChart.data.labels =
                Object.keys(data);

            hourlyChart.data.datasets[0].data =
                Object.values(data);

            hourlyChart.update();

            document.getElementById(
                "hourly-title"
            ).innerText =
                "Login Attempts Per Hour (" +
                selectedDay +
                ")";
        });

    };

    hourlyChart = new Chart(
        document.getElementById("hourlyChart"),
        {
            type: "bar",

            data: {
                labels: dashboardData.hourlyLabels,

                datasets: [{
                    label: "Events Per Hour",
                    data: dashboardData.hourlyCounts
                }]
            }
        }
    );

    threatChart = new Chart(
        document.getElementById("threatChart"),
        {
            type: "doughnut",
            data: {
                labels: dashboardData.threatLabels,
                
                datasets: [{
                    label: "Detected Threats",
                    data: dashboardData.threatCounts
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'right',
                        align: 'center',
                        
                        labels: {
                            boxWidth: 25,
                            padding: 15 
                        }
                    }
                }
            }
        }
    );

    document.getElementById("reset-hourly")
        .addEventListener("click", function(){

            selectedDay = null;

            document.getElementById(
                "hourly-title"
            ).innerText =
            "Login Attempts Per Hour (Today)";

            updateDashboard();

        }
    );

    document
    .getElementById("analytics-filter")
    .addEventListener("change",function(){

        analyticsFilter=this.value;
        updateDashboard();

    });
}
      
function updateDashboard() {

    fetch(
        "/dashboard-data?days=" +
        analyticsFilter
    )

    .then(response => response.json())
    .then(data => {
        document.getElementById(
            "total-events"
        ).innerText = data.total_events;

        document.getElementById(
            "successful-logins"
        ).innerText = data.successful_logins;

        document.getElementById(
            "failed-logins"
        ).innerText = data.failed_logins;

        loginChart.data.datasets[0].data = [
            data.successful_logins,
            data.failed_logins
        ];

        loginChart.update();

        eventChart.data.datasets[0].data = [
            data.total_events,
            data.successful_logins,
            data.failed_logins
        ];

        eventChart.update();

        usernameChart.data.labels =
            data.top_usernames.map(item => item[0]);

        usernameChart.data.datasets[0].data =
            data.top_usernames.map(item => item[1]);

        usernameChart.update();

        ipChart.data.labels =
            data.top_ips.map(item => item[0]);

        ipChart.data.datasets[0].data =
            data.top_ips.map(item => item[1]);

        ipChart.update();

        dailyChart.data.labels =
            Object.keys(data.daily_activity);

        dailyChart.data.datasets[0].data =
            Object.values(data.daily_activity);

        dailyChart.update();

        if(selectedDay){
            fetch("/hourly/" + selectedDay)
            .then(response => response.json())
            .then(hourlyData => {

                hourlyChart.data.labels =
                    Object.keys(hourlyData);

                hourlyChart.data.datasets[0].data =
                    Object.values(hourlyData);

                hourlyChart.update();

            });

        }
        else{
            hourlyChart.data.labels =
                Object.keys(data.hourly_activity);

            hourlyChart.data.datasets[0].data =
                Object.values(data.hourly_activity);

            hourlyChart.update();

        }

        threatChart.data.labels =
            Object.keys(data.threat_distribution);

        threatChart.data.datasets[0].data =
            Object.values(data.threat_distribution);

        threatChart.update();

        const eventsBody =
            document.getElementById("events-body");

        eventsBody.innerHTML = "";

        data.recent_events.forEach(event => {

            let color =
                event.event_type === "LOGIN_SUCCESS"
                ? "green"
                : "red";

            eventsBody.innerHTML += `
                <tr>
                    <td>${event.timestamp}</td>
                    <td style="color:${color}">${event.event_type}</td>
                    <td>${event.username}</td>
                    <td>${event.ip_address}</td>
                </tr>
            `;

        });

        const threatContainer =
            document.getElementById("threat-container");

        threatContainer.innerHTML = "";

        data.brute_force_alerts.forEach(alert => {

            threatContainer.innerHTML += `
            <div class="card border-danger p-3 col-mb-3">
                <h3 style="color:red;">
                    🚨 BRUTE FORCE ATTACK
                </h3>

                <p>IP : ${alert.ip}</p>
                <p>Attempts : ${alert.attempts}</p>
            </div>
            `;
        });

        data.credential_alerts.forEach(alert => {

            threatContainer.innerHTML += `

                <div class="card border-danger p-3 col-mb-3">
                    <h3 style="color:red;">HIGH ALERT</h3>

                    <p>Credential Stuffing Detected</p>
                    <p>IP: ${alert.ip}</p>
                    <p>Username: ${alert.username}</p>
                    <p>Attempts: ${alert.attempts}</p>
                </div>
            `;
        });

        data.enumeration_alerts.forEach(alert => {

            threatContainer.innerHTML += `
                <div class="card border-warning p-3 col-mb-3">
                    
                    <h3 style="color:orange;">MEDIUM ALERT</h3>

                    <p>Username Enumeration Detected</p>
                    <p>IP: ${alert.ip}</p>
                    <p>Usernames Tried: ${alert.user_count}</p>
                </div>
            `;
        });

        data.mixed_alerts.forEach(alert => {

            threatContainer.innerHTML += `
                <div class="card border-dark p-3 col-mb-3">
                    <h3 style="color:purple;">
                        🚨 MIXED ATTACK
                    </h3>
                    <p>IP: ${alert.ip}</p>
                    <p>Attempts: ${alert.attempts}</p>
                    <p>Usernames: ${alert.usernames}</p>
                </div>
            `;
        });

        const historyBody =
            document.getElementById("threat-history-body").reverse();

        historyBody.innerHTML = "";

        data.threat_history.forEach(threat => {
 
            historyBody.innerHTML += `
                <tr>
                    <td>${threat.timestamp}</td>
                    <td>${threat.severity}</td>
                    <td>${threat.threat_type}</td>
                    <td>${threat.ip}</td>
                    <td>${threat.username}</td>
                    <td>${threat.status}</td>
                    <td>${threat.reason}</td>
                    <td>${threat.impact}</td>
                </tr>
            `;
        });
    });
}

initializeCharts();
updateDashboard();
setInterval(updateDashboard, 5000);
