import {formatISO9075} from "date-fns";
import {Link} from "react-router-dom";

export default function Post({_id, title, summary, cover, coverUrl, createdAt, author}) {
  return (
    <div className="post">
      <div className="image">
        <Link to={`/post/${_id}`}>
          <img 
            src={coverUrl || `${process.env.REACT_APP_API_URL}/uploads/${cover}`} 
            alt={title}
            style={{
              width: '100%',
              height: '250px',
              objectFit: 'cover',
              objectPosition: 'center'
            }}
          />
        </Link>
      </div>
      <div className="texts">
        <Link to={`/post/${_id}`}>
          <h2>{title}</h2>
        </Link>
        <p className="info">
          <span className="author">{author?.username || 'Unknown'}</span>
          <time>{formatISO9075(new Date(createdAt))}</time>
        </p>
        <p className="summary">{summary}</p>
      </div>
    </div>
  );
}
