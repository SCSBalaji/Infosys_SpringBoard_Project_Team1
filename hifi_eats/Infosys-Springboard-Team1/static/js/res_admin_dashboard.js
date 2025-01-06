           // Donut Chart
           const donutCtx = document.getElementById('donutChart').getContext('2d');
           const donutChart = new Chart(donutCtx, {
               type: 'doughnut',
               data: {
                   labels: ['Successful', 'Failed', 'Pending'],
                   datasets: [{
                       data: [70, 20, 10], // Replace with real data
                       backgroundColor: ['#28a745', '#dc3545', '#ffc107'],
                       borderColor: ['#28a745', '#dc3545', '#ffc107'],
                       borderWidth: 1
                   }]
               },
               options: {
                   responsive: true,
                   plugins: {
                       legend: {
                           position: 'top',
                       },
                       tooltip: {
                           enabled: true
                       }
                   }
               }
           });
           
           //(Line Chart Example)
           const stockPriceCtx = document.getElementById('stockPriceChart').getContext('2d');
           const stockPriceChart = new Chart(stockPriceCtx, {
               type: 'line',
               data: {
                   labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
                   datasets: [{
                       label: 'Item Price',
                       data: [150, 200, 180, 210, 250], // Replace with real data
                       borderColor: '#007bff',
                       borderWidth: 2,
                       fill: false
                   }]
               },
               options: {
                   responsive: true,
                   plugins: {
                       legend: {
                           position: 'top',
                       },
                       tooltip: {
                           enabled: true
                       }
                   }
               }
           });
           
           //  (Bar Chart Example)
           const ipoPerformanceCtx = document.getElementById('ipoPerformanceChart').getContext('2d');
           const ipoPerformanceChart = new Chart(ipoPerformanceCtx, {
               type: 'bar',
               data: {
                   labels: ['IPO1', 'IPO2', 'IPO3', 'IPO4'],
                   datasets: [{
                       label: 'Performance',
                       data: [90, 65, 75, 85], // Replace with real data
                       backgroundColor: '#ffc107',
                       borderColor: '#ffc107',
                       borderWidth: 1
                   }]
               },
               options: {
                   responsive: true,
                   plugins: {
                       legend: {
                           position: 'top',
                       },
                       tooltip: {
                           enabled: true
                       }
                   }
               }
           });
           
           // Volume Chart (Radar Chart Example)
                       const volumeCtx = document.getElementById('volumeChart').getContext('2d');
                       const volumeChart = new Chart(volumeCtx, {
                           type: 'radar',
                           data: {
                               labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
                               datasets: [{
                                   label: 'Volume',
                                   data: [200, 150, 180, 220, 250], // Replace with real data
                                   backgroundColor: 'rgba(0, 123, 255, 0.2)',
                                   borderColor: 'rgba(0, 123, 255, 1)',
                                   borderWidth: 1
                               }]
                           },
                           options: {
                               responsive: true,
                               plugins: {
                                   legend: {
                                       position: 'top',
                                   },
                                   tooltip: {
                                       enabled: true
                                   }
                               }
                           }
                       });
           
                   document.addEventListener('DOMContentLoaded', () => {
               function toggleSidebar() {
                   const sidebar = document.querySelector('.sidebar');
                   const hamburger = document.querySelector('.hamburger');
                   if (sidebar.style.left === '0px') {
                       sidebar.style.left = '-250px';
                       hamburger.classList.remove('active');
                   } else {
                       sidebar.style.left = '0px';
                       hamburger.classList.add('active');
                   }
               }
           
               const sidebarLinks = document.querySelectorAll('.sidebar .menu ul li a');
               const mainContent = document.getElementById('mainContent');
           
               const sections = {
                   dashboard: `<h1>Reports Section</h1><p>This is the reports section.</p>`,
                   'manage-menu': `<h1>Admin Notifications </h1><p>Here you can get notifications.</p>`,
                   'sales-insights': `<h1>Sales Insights</h1><p>View insights on your sales data.</p>`,
                   'customer-insights': `<h1>Customer Insights</h1><p>Analyze customer feedback and data.</p>`,
                   settings: `<h1>Settings</h1><p>Manage your account settings here.</p>`,
                   'api-manager': `<h1>API Manager</h1><p>Manage your API integrations here.</p>`,
                   accounts: `<h1>Accounts</h1><p>View and manage account information.</p>`,
                   help: `<h1>Help</h1><p>Get help and support here.</p>`
               };
           
               sidebarLinks.forEach(link => {
                   link.addEventListener('click', (e) => {
                       e.preventDefault();
                       const section = link.dataset.section;
                       console.log(`Section clicked: ${section}`); // Debug log
                       if (sections[section]) {
                           mainContent.innerHTML = sections[section];
                       } else {
                           console.error(`No content defined for section: ${section}`);
                       }
                   });
               });
           });
           