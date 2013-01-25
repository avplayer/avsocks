#pragma once

#include <boost/shared_ptr.hpp>

#ifndef WXWIDGETS_AVSOCKS_UI
#define WXWIDGETS_AVSOCKS_UI

#include <wx/wxprec.h>
#include <wx/wx.h>
#include <wx/taskbar.h>

class task_bar;

class avsocks_ui : public wxFrame
{
public:
    avsocks_ui(const wxString& title);
    ~avsocks_ui(){stop_=true;}
public:
    boost::shared_ptr<wxPanel>          panel_;
    boost::shared_ptr<wxButton>         start_button_;
    boost::shared_ptr<wxTextCtrl>       server_ip_;
    boost::shared_ptr<wxTextCtrl>       server_port_;
    boost::shared_ptr<wxCheckBox>       server_mode_;
    boost::shared_ptr<boost::thread>    thread_;
    boost::shared_ptr<task_bar>         task_bar_;

public:
    void on_start(wxCommandEvent &event);
    void on_server_mode(wxCommandEvent &event);

public:
    void do_accept(ip::tcp::acceptor &accepter, socketptr avsocketclient, const boost::system::error_code &ec);

public:
    boost::asio::io_service io_;
    socketptr               socket_;
    asio::ip::tcp::acceptor acceptor_;
    bool                    stop_;
};

class task_bar: public wxTaskBarIcon
{
public:
    task_bar(avsocks_ui* ui):ui_(ui){}
    void OnLeftButtonDown(wxTaskBarIconEvent&)
    {
        ui_->Show(true);   
    }
    DECLARE_EVENT_TABLE()
public:
    avsocks_ui* ui_;
};

BEGIN_EVENT_TABLE(task_bar, wxTaskBarIcon)
EVT_TASKBAR_LEFT_DOWN  (task_bar::OnLeftButtonDown)
END_EVENT_TABLE()


class avsocks_app : public wxApp
{   
public:
    virtual bool OnInit();
private:
    avsocks_ui* ui;
};

IMPLEMENT_APP(avsocks_app)

bool avsocks_app::OnInit()
{
    ui=new avsocks_ui(wxT("avsocks 0.1"));
    return ui->Show(true);
}

avsocks_ui::avsocks_ui(const wxString& title): wxFrame(NULL, wxID_ANY, title, wxDefaultPosition, wxSize(210, 100),wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX),acceptor_(io_),stop_(false)
{
    panel_.reset(new wxPanel(this, wxID_ANY));

    start_button_.reset(new wxButton(panel_.get(),1, wxT("start"),wxPoint(115, 40)));

    Connect(1, wxEVT_COMMAND_BUTTON_CLICKED, 
        wxCommandEventHandler(avsocks_ui::on_start));

    start_button_->SetFocus();

    server_ip_.reset(new wxTextCtrl(panel_.get(), -1, wxT("localhost"),  wxPoint(10,10), wxSize(100, 20)));
    server_ip_->SetForegroundColour(*wxBLUE);
    server_ip_->SetBackgroundColour(*wxLIGHT_GREY);

    wxTextValidator validator(wxFILTER_NUMERIC); 

    server_port_.reset(new wxTextCtrl(panel_.get(), -1, wxT("4567"),       wxPoint(120,10),wxSize(50,20),0,validator));

    server_port_->SetForegroundColour(*wxBLUE);
    server_port_->SetBackgroundColour(*wxLIGHT_GREY);
    server_port_->SetMaxLength(5);

    server_mode_.reset(new wxCheckBox(panel_.get(), 2, wxT("server_mode"),wxPoint(10,40)));

    Connect(2, wxEVT_COMMAND_CHECKBOX_CLICKED, 
        wxCommandEventHandler(avsocks_ui::on_server_mode));

    SetIcon(wxIcon(wxT("application_icon")));

    Centre();
}

void avsocks_ui::on_server_mode(wxCommandEvent &event)
{
    server_mode_->IsChecked()?server_ip_->Enable(false):server_ip_->Enable(true);
}

// 一个简单的accept服务器, 用于不停的异步接受客户端的连接, 连接可能是socks5连接或ssl加密数据连接.

void avsocks_ui::do_accept(ip::tcp::acceptor &accepter, socketptr avsocketclient, const boost::system::error_code &ec)
{
    // socket对象
    if(!ec)
    {
        // 使得这个avsocketclient构造一个avclient对象, 并start进入工作.
        avclient::new_avclient(io_, avsocketclient);
    }

    if (stop_)
        return;

    // 创建新的socket, 进入侦听, .
    avsocketclient.reset(new ip::tcp::socket(accepter.get_io_service()));
    accepter.async_accept(*avsocketclient,
        boost::bind(&avsocks_ui::do_accept,this,boost::ref(accepter), avsocketclient, asio::placeholders::error));
}
#endif