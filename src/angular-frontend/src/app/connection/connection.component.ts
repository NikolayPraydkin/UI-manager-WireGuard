import {Component} from '@angular/core';

@Component({
  selector: 'app-connection',
  templateUrl: './connection.component.html',
  styleUrls: ['./connection.component.css']
})
export class ConnectionComponent {

  login: String = ''
  password: String = ''

  getLogin(){
    return this.login;
  }

  connect() {
    if(this.login !== '' && this.password !== ''){
      console.log('connect')
    }
  }
}
