from os import name
from django import urls
from django.urls import path
from .import views
urlpatterns = [
    path('', views.home, name="home"),
    path('options/', views.options_screen, name="options"),
    path('services/', views.services, name="services"),
    path('connected-devices', views.connected_devices, name='connected-devices'),
    path('port-enable/', views.port_enable, name="port-enable"),
    path('port-reset/', views.port_reset, name="port-reset"),
    path('port-disable/', views.port_disable, name="port-disable"),
    path('port-allow/', views.port_allow, name='port-allow'),
    path('system-information', views.show_system_information, name='system-information'),
    path('load-balancer/', views.start_LoadBalancer, name='load-balancer'),
    path('maltrail/', views.maltrail_home, name='maltrail'),
    path('superuser/', views.run_superuser, name='run-superuser'),
    path('maltrail-server-enable/', views.maltrail_server, name='maltrail-server'),
    path('maltrail-sensor-enable/', views.maltrail_sensor, name='maltrail-sensor'),
    path('ip-blacklist-form', views.ip_blacklist_form, name='ip-blacklist-form'),
    path('ip-blacklist-logs', views.ip_blacklist_logs, name='ip-blacklist-logs'),
    path('ip-whitelist-form', views.ip_whitelist_form, name='ip-whitelist-form'),
]