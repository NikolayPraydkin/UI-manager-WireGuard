import {Component} from '@angular/core';
import {HttpClient, HttpErrorResponse, HttpParams} from "@angular/common/http";
import {catchError, throwError} from "rxjs";

@Component({
  selector: 'app-connection',
  templateUrl: './connection.component.html',
  styleUrls: ['./connection.component.css']
})
export class ConnectionComponent {

  host: string = ''
  port?: number
  login: string = ''
  password: string = ''
  result: any = ''

  constructor(private http: HttpClient) {
  }

  getLogin() {
    return this.login;
  }

  connect(): void {
    if (this.login !== '' && this.password !== '') {
      let httpParams = new HttpParams().appendAll({'host': this.host, 'user': this.login, 'password': this.password});
      if (this.port !== undefined) {
        httpParams.append('port', this.port)
      }
      this.http.get('http://localhost:8080/connectSSHByPassword',
        {responseType: 'text', observe: 'response', params: httpParams})
        .pipe(catchError((e) => this.handleError(e)))
        .subscribe(data => this.result = data.body);
    }
  }

  handleError(error: HttpErrorResponse) {
    if (error.status === 0) {
      // A client-side or network error occurred. Handle it accordingly.
      console.error('An error occurred:', error.error);
    } else {
      // The backend returned an unsuccessful response code.
      // The response body may contain clues as to what went wrong.

      this.result = error.error
      console.error(
        `Backend returned code ${error.status}, body was: `, error.error);
    }
    // Return an observable with a user-facing error message.
    return throwError(() => new Error('Something bad happened; please try again later.'));
  }
}
